//! Out-of-band identity — compact runtime handshake (Phase 1).
//!
//! The full handshake (`crypto::generic`) carries, on every connection, each
//! peer's ML-DSA-65 **public key** (1952 B) and a fresh ML-DSA-65 **signature**
//! (3309 B). That is ~10.5 KB of post-quantum identity material on the runtime
//! wire per handshake, and an ML-DSA sign + verify on the latency path.
//!
//! This module moves the ML-DSA exchange **off the runtime path**:
//!
//!   * the peer's full identity (Ed25519 + ML-DSA-65 public keys) is provisioned
//!     **out-of-band** into a [`PeerRegistry`] (in practice via the identity
//!     credential lifecycle — itself ML-DSA-authenticated);
//!   * a per-peer **`auth_secret`** is established during a one-time, PQ-
//!     authenticated provisioning handshake (`derive_provisioning_auth_secret`
//!     binds it to a full handshake's session keys);
//!   * at runtime the peer is referenced by a 32-byte [`IdentityKeyHash`] and
//!     authenticated by a 32-byte HMAC capability ([`SessionToken`] semantics)
//!     under the shared `auth_secret` — replacing the ML-DSA key+signature.
//!
//! The KEM exchange (X25519 + ML-KEM) is unchanged, so **confidentiality and
//! forward secrecy are identical**. Mutual authentication is preserved: each side
//! proves possession of the shared `auth_secret` over the transcript (a symmetric
//! MAC, so it is itself post-quantum secure). There is **no plaintext fallback** —
//! an unknown hash, a bad tag, or an expired entry all fail closed.

use std::collections::{HashMap, HashSet};

use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use ml_kem::MlKem768;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use super::generic::{self, OobInitiatorState};
use super::{CryptoError, SessionKeys};

/// ML-KEM-768 wire sizes (the OOB engine uses suite 768).
const EK_LEN: usize = 1184;
const CT_LEN: usize = 1088;
const OOB_SUITE_ID: u8 = 0x01;

const AUTH_SECRET_LEN: usize = 32;
const PROVISION_INFO: &[u8] = b"syntriass-overlay oob peer-auth secret v1";

/// A compact, collision-resistant reference to a peer identity: the SHA-256 of
/// its full public-key material (`ed25519_pub || mldsa65_pub`). Carried on the
/// runtime wire instead of the 1952-byte ML-DSA public key.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct IdentityKeyHash(pub [u8; 32]);

impl IdentityKeyHash {
    pub fn of(ed25519_pub: &[u8], mldsa65_pub: &[u8]) -> Self {
        let mut h = Sha256::new();
        h.update(b"syntriass-overlay identity-key-hash v1");
        h.update(ed25519_pub);
        h.update(mldsa65_pub);
        Self(h.finalize().into())
    }
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// A short-lived, epoch-bound session authorization token derived from the
/// long-lived per-peer `auth_secret`. Both peers hold the same `auth_secret`, so
/// both derive (and can verify) the identical token for a given epoch; rotating
/// the epoch rotates the token without re-provisioning. Comparison is
/// constant-time.
///
/// **Scope:** [implemented] + [tested] as a typed, rotating capability over the
/// provisioned secret. It is **not yet carried on the runtime handshake wire**
/// (the runtime handshake authenticates with the per-transcript HMAC capability
/// in `generic::oob_*`); binding the `SessionToken` into that transcript is
/// tracked as [design] in `docs/OUT_OF_BAND_IDENTITY.md`.
#[derive(Clone)]
pub struct SessionToken([u8; 32]);

impl SessionToken {
    /// Derive the token for `epoch` from a peer's `auth_secret`.
    fn derive(auth_secret: &[u8], epoch: u64) -> Self {
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(auth_secret)
            .expect("HMAC accepts any key length");
        mac.update(b"syntriass-overlay oob session-token v1");
        mac.update(&epoch.to_le_bytes());
        Self(mac.finalize().into_bytes().into())
    }

    /// Constant-time equality (no early-exit timing oracle on the token).
    pub fn verify(&self, other: &SessionToken) -> bool {
        use subtle::ConstantTimeEq;
        self.0.ct_eq(&other.0).into()
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Derive the long-lived per-peer `auth_secret` from a PQ-authenticated
/// provisioning handshake's established keys. Run **once** at provisioning; the
/// secret is then registered and used for many compact runtime handshakes.
pub fn derive_provisioning_auth_secret(keys: &SessionKeys) -> Zeroizing<[u8; AUTH_SECRET_LEN]> {
    // Bind to BOTH directions' kTLS-export key material so the secret is unique to
    // this provisioning session and unknown without having completed it. The two
    // keys are combined in a **role-independent** (sorted) order so the initiator
    // and responder derive the identical shared secret (initiator tx == responder
    // rx and vice versa).
    let k = keys.export_ktls();
    let (lo, hi) = if k.tx.key <= k.rx.key {
        (&k.tx.key, &k.rx.key)
    } else {
        (&k.rx.key, &k.tx.key)
    };
    let mut ikm = Zeroizing::new(Vec::with_capacity(64));
    ikm.extend_from_slice(lo);
    ikm.extend_from_slice(hi);
    let hk = Hkdf::<Sha256>::new(None, &ikm);
    let mut out = Zeroizing::new([0u8; AUTH_SECRET_LEN]);
    hk.expand(PROVISION_INFO, out.as_mut())
        .expect("32 bytes within HKDF bounds");
    out
}

/// One provisioned peer: its full (out-of-band) identity plus the shared
/// `auth_secret` and an optional expiry (lifecycle integration).
pub struct PeerRecord {
    pub ed25519_pub: [u8; 32],
    pub mldsa65_pub: Vec<u8>,
    auth_secret: Zeroizing<[u8; AUTH_SECRET_LEN]>,
    pub not_after: u64, // 0 = no expiry
}

impl PeerRecord {
    pub fn new(
        ed25519_pub: [u8; 32],
        mldsa65_pub: Vec<u8>,
        auth_secret: [u8; AUTH_SECRET_LEN],
        not_after: u64,
    ) -> Self {
        Self {
            ed25519_pub,
            mldsa65_pub,
            auth_secret: Zeroizing::new(auth_secret),
            not_after,
        }
    }
    fn hash(&self) -> IdentityKeyHash {
        IdentityKeyHash::of(&self.ed25519_pub, &self.mldsa65_pub)
    }

    /// The session token authorizing this peer for `epoch` (see [`SessionToken`]).
    pub fn session_token(&self, epoch: u64) -> SessionToken {
        SessionToken::derive(&self.auth_secret[..], epoch)
    }

    /// Whether this record's lifetime covers `now` (0 = no expiry).
    pub fn is_valid_at(&self, now: u64) -> bool {
        self.not_after == 0 || now < self.not_after
    }
}

/// Out-of-band peer identity registry + cache. Provisioned out-of-band; the
/// runtime handshake resolves peers by [`IdentityKeyHash`] here. Lookups are
/// O(1) (the `HashMap` is the cache). Fail-closed: an unknown hash yields no
/// record and the handshake aborts.
#[derive(Default)]
pub struct PeerRegistry {
    by_hash: HashMap<[u8; 32], PeerRecord>,
    revoked: HashSet<[u8; 32]>,
    hits: u64,
    misses: u64,
}

impl PeerRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Provision a peer (out-of-band). Returns its `IdentityKeyHash`. Provisioning
    /// also clears any prior revocation of that exact identity (re-instatement is
    /// an explicit operator action).
    pub fn provision(&mut self, record: PeerRecord) -> IdentityKeyHash {
        let h = record.hash();
        self.revoked.remove(&h.0);
        self.by_hash.insert(h.0, record);
        h
    }

    /// Cache lookup by hash (records a hit/miss for the cache metrics).
    /// **Fail-closed:** a revoked hash yields `None` (counted as a miss) even
    /// though the record may still be present — a revoked identity can never
    /// resolve, so it can neither initiate nor be responded to.
    pub fn lookup(&mut self, hash: &IdentityKeyHash) -> Option<&PeerRecord> {
        if self.revoked.contains(&hash.0) {
            self.misses += 1;
            return None;
        }
        if self.by_hash.contains_key(&hash.0) {
            self.hits += 1;
            self.by_hash.get(&hash.0)
        } else {
            self.misses += 1;
            None
        }
    }

    /// Revoke an identity. Subsequent lookups fail closed. Idempotent; revoking an
    /// unknown hash is allowed (pre-emptive revocation).
    pub fn revoke(&mut self, hash: &IdentityKeyHash) {
        self.revoked.insert(hash.0);
    }

    /// Lift a revocation (re-instate). Returns whether the hash was revoked.
    pub fn unrevoke(&mut self, hash: &IdentityKeyHash) -> bool {
        self.revoked.remove(&hash.0)
    }

    /// Whether `hash` is currently revoked.
    pub fn is_revoked(&self, hash: &IdentityKeyHash) -> bool {
        self.revoked.contains(&hash.0)
    }

    /// Number of revoked identities.
    pub fn revoked_count(&self) -> usize {
        self.revoked.len()
    }

    pub fn len(&self) -> usize {
        self.by_hash.len()
    }
    pub fn is_empty(&self) -> bool {
        self.by_hash.is_empty()
    }
    /// (hits, misses) cache counters.
    pub fn cache_stats(&self) -> (u64, u64) {
        (self.hits, self.misses)
    }
}

/// Retained initiator state for a runtime OOB handshake.
pub struct OobInit {
    inner: OobInitiatorState<MlKem768>,
    expected_server_hash: [u8; 32],
    auth_secret: Zeroizing<[u8; AUTH_SECRET_LEN]>,
}

/// Begin a compact runtime handshake to a registered peer. `own_hash` is this
/// node's `IdentityKeyHash`; `peer` is resolved from the registry by the caller.
pub fn begin_initiator(
    own_hash: &IdentityKeyHash,
    peer: &PeerRecord,
    now: u64,
) -> Result<(OobInit, Vec<u8>), CryptoError> {
    if peer.not_after != 0 && now >= peer.not_after {
        return Err(CryptoError::BadIdentityConfig); // expired -> fail closed
    }
    let (inner, hello) =
        generic::oob_client_hello::<MlKem768>(OOB_SUITE_ID, &own_hash.0, &peer.auth_secret[..])?;
    Ok((
        OobInit {
            inner,
            expected_server_hash: peer.hash().0,
            auth_secret: peer.auth_secret.clone(),
        },
        hello,
    ))
}

/// Responder: resolve the client by its embedded hash via the registry, verify
/// the capability, and respond. Returns the established keys, the ServerHello, and
/// the authenticated peer's hash. Fail-closed on unknown/expired peer or bad tag.
pub fn respond(
    own_hash: &IdentityKeyHash,
    registry: &mut PeerRegistry,
    now: u64,
    client_hello: &[u8],
) -> Result<(SessionKeys, Vec<u8>, IdentityKeyHash), CryptoError> {
    let client_hash = IdentityKeyHash(generic::oob_client_hash(client_hello, EK_LEN)?);
    let peer = registry
        .lookup(&client_hash)
        .ok_or(CryptoError::Authentication)?;
    if peer.not_after != 0 && now >= peer.not_after {
        return Err(CryptoError::BadIdentityConfig);
    }
    let auth_secret = peer.auth_secret.clone();
    let (keys, hello) = generic::oob_respond::<MlKem768>(
        OOB_SUITE_ID,
        EK_LEN,
        &own_hash.0,
        &auth_secret[..],
        client_hello,
    )?;
    Ok((keys, hello, client_hash))
}

/// Initiator step 2: verify the server capability + identity and finish.
pub fn finish(state: OobInit, server_hello: &[u8]) -> Result<SessionKeys, CryptoError> {
    generic::oob_finish::<MlKem768>(
        state.inner,
        CT_LEN,
        &state.expected_server_hash,
        &state.auth_secret[..],
        server_hello,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{
        derive_identity_public_keys, CipherSuite, IdentityMaterial, ED25519_SEED_LEN,
        MLDSA65_SEED_LEN,
    };

    /// Provision two peers that trust each other via a one-time PQ handshake, then
    /// register each other with the derived auth_secret. Returns (client_reg,
    /// server_reg, client_hash, server_hash).
    fn provision() -> (
        PeerRegistry,
        PeerRegistry,
        IdentityKeyHash,
        IdentityKeyHash,
        Vec<u8>,
        Vec<u8>,
    ) {
        let (ce, cm) = ([0x11u8; ED25519_SEED_LEN], [0x22u8; MLDSA65_SEED_LEN]);
        let (se, sm) = ([0x33u8; ED25519_SEED_LEN], [0x44u8; MLDSA65_SEED_LEN]);
        let (ce_pub, cm_pub) = derive_identity_public_keys(&ce, &cm).unwrap();
        let (se_pub, sm_pub) = derive_identity_public_keys(&se, &sm).unwrap();
        let client_id = IdentityMaterial::from_bytes(ce, cm, se_pub, sm_pub.clone()).unwrap();
        let server_id = IdentityMaterial::from_bytes(se, sm, ce_pub, cm_pub.clone()).unwrap();

        // One-time PQ-authenticated provisioning handshake (full ML-DSA path).
        let engine = CipherSuite::NistStandard768.engine();
        let (st, ch) = engine.begin_initiator(&client_id).unwrap();
        let (server_keys, sh) = engine.respond(&server_id, &ch).unwrap();
        let client_keys = st.finish(&client_id, &sh).unwrap();
        let secret_c = derive_provisioning_auth_secret(&client_keys);
        let secret_s = derive_provisioning_auth_secret(&server_keys);
        assert_eq!(
            &secret_c[..],
            &secret_s[..],
            "both sides derive the same auth_secret"
        );

        let client_hash = IdentityKeyHash::of(&ce_pub, &cm_pub);
        let server_hash = IdentityKeyHash::of(&se_pub, &sm_pub);

        // Each registers the OTHER with the shared secret.
        let mut client_reg = PeerRegistry::new();
        client_reg.provision(PeerRecord::new(se_pub, sm_pub.clone(), *secret_c, 0));
        let mut server_reg = PeerRegistry::new();
        server_reg.provision(PeerRecord::new(ce_pub, cm_pub.clone(), *secret_s, 0));

        (
            client_reg,
            server_reg,
            client_hash,
            server_hash,
            cm_pub,
            sm_pub,
        )
    }

    #[test]
    fn oob_handshake_round_trips_and_keys_agree() {
        let (mut creg, mut sreg, chash, shash, _cm, _sm) = provision();
        let peer = creg.lookup(&shash).unwrap();
        let (st, ch) = begin_initiator(&chash, peer, 1_000).unwrap();
        let (mut sk, sh, who) = respond(&shash, &mut sreg, 1_000, &ch).unwrap();
        assert_eq!(who, chash, "responder authenticated the right client");
        let mut ck = finish(st, &sh).unwrap();

        // Keys agree: seal on one side opens on the other.
        let m = b"oob-channel-ok";
        let ct = ck.seal(m).unwrap();
        assert_eq!(sk.open(&ct).unwrap(), m);
    }

    #[test]
    fn oob_handshake_carries_no_mldsa() {
        let (mut creg, mut sreg, chash, shash, cm_pub, sm_pub) = provision();
        let peer = creg.lookup(&shash).unwrap();
        let (_st, ch) = begin_initiator(&chash, peer, 1_000).unwrap();
        let (_sk, sh, _who) = respond(&shash, &mut sreg, 1_000, &ch).unwrap();
        // SUCCESS CRITERIA: neither hello contains the ML-DSA public key or a
        // 3309-byte signature. Check by searching for the (large) ML-DSA pubkeys.
        for hello in [&ch, &sh] {
            assert!(
                !hello.windows(cm_pub.len()).any(|w| w == cm_pub.as_slice()),
                "ML-DSA public key leaked onto the runtime wire"
            );
            assert!(
                !hello.windows(sm_pub.len()).any(|w| w == sm_pub.as_slice()),
                "ML-DSA public key leaked onto the runtime wire"
            );
            assert!(
                hello.len() < 1500,
                "OOB hello unexpectedly large: {}",
                hello.len()
            );
        }
    }

    #[test]
    fn unknown_peer_fails_closed() {
        let (_creg, mut sreg, _chash, shash, _cm, _sm) = provision();
        // A client whose identity was never provisioned.
        let mut reg2 = PeerRegistry::new();
        reg2.provision(PeerRecord::new([0x99; 32], vec![0x99; 1952], [0x12; 32], 0));
        let stranger = IdentityKeyHash::of(&[0x99; 32], &[0x99; 1952][..]);
        let peer = reg2.lookup(&stranger).unwrap();
        let (_st, ch) = begin_initiator(&stranger, peer, 1_000).unwrap();
        // The server has never heard of this client hash -> Authentication error.
        assert_eq!(
            respond(&shash, &mut sreg, 1_000, &ch).unwrap_err(),
            CryptoError::Authentication
        );
    }

    #[test]
    fn tampered_capability_fails_closed() {
        let (mut creg, mut sreg, chash, shash, _cm, _sm) = provision();
        let peer = creg.lookup(&shash).unwrap();
        let (_st, mut ch) = begin_initiator(&chash, peer, 1_000).unwrap();
        let last = ch.len() - 1;
        ch[last] ^= 0x01; // flip a tag bit
        assert_eq!(
            respond(&shash, &mut sreg, 1_000, &ch).unwrap_err(),
            CryptoError::Authentication
        );
    }

    #[test]
    fn wrong_auth_secret_fails_closed() {
        let (mut creg, _sreg, chash, shash, cm_pub, _sm) = provision();
        // A server that registered the client with the WRONG shared secret.
        let (ce, cm) = ([0x11u8; ED25519_SEED_LEN], [0x22u8; MLDSA65_SEED_LEN]);
        let (ce_pub, _) = derive_identity_public_keys(&ce, &cm).unwrap();
        let mut bad_sreg = PeerRegistry::new();
        bad_sreg.provision(PeerRecord::new(ce_pub, cm_pub, [0xAB; 32], 0));
        let peer = creg.lookup(&shash).unwrap();
        let (_st, ch) = begin_initiator(&chash, peer, 1_000).unwrap();
        assert_eq!(
            respond(&shash, &mut bad_sreg, 1_000, &ch).unwrap_err(),
            CryptoError::Authentication
        );
    }

    #[test]
    fn expired_peer_fails_closed() {
        let (_creg, _sreg, chash, shash, cm_pub, _sm) = provision();
        let (ce, cm) = ([0x11u8; ED25519_SEED_LEN], [0x22u8; MLDSA65_SEED_LEN]);
        let (ce_pub, _) = derive_identity_public_keys(&ce, &cm).unwrap();
        let mut creg2 = PeerRegistry::new();
        // peer expires at 2000
        let phash = creg2.provision(PeerRecord::new(ce_pub, cm_pub.clone(), [0x01; 32], 2_000));
        let _ = (chash, shash);
        let peer = creg2.lookup(&phash).unwrap();
        assert!(matches!(
            begin_initiator(&chash, peer, 3_000),
            Err(CryptoError::BadIdentityConfig)
        ));
    }

    #[test]
    fn cache_lookup_succeeds() {
        let (mut creg, _s, _ch, shash, _cm, _sm) = provision();
        assert!(creg.lookup(&shash).is_some());
        let (hits, misses) = creg.cache_stats();
        assert_eq!((hits, misses), (1, 0));
        assert!(creg.lookup(&IdentityKeyHash([0xEE; 32])).is_none());
        assert_eq!(creg.cache_stats(), (1, 1));
    }

    #[test]
    fn revoked_identity_fails_closed_on_a_real_handshake() {
        // Healthy: the runtime OOB handshake round-trips before revocation.
        let (mut creg, mut sreg, chash, shash, _cm, _sm) = provision();
        let peer = creg.lookup(&shash).unwrap();
        let (st, ch) = begin_initiator(&chash, peer, 1_000).unwrap();
        let (mut sk, sh, who) = respond(&shash, &mut sreg, 1_000, &ch).unwrap();
        assert_eq!(who, chash);
        let mut ck = finish(st, &sh).unwrap();
        let ct = ck.seal(b"pre-revocation").unwrap();
        assert_eq!(sk.open(&ct).unwrap(), b"pre-revocation");

        // The server revokes the client's identity. The very next handshake must
        // fail closed: the responder no longer resolves the revoked hash.
        assert!(!sreg.is_revoked(&chash));
        sreg.revoke(&chash);
        assert!(sreg.is_revoked(&chash));
        assert_eq!(sreg.revoked_count(), 1);

        let peer = creg.lookup(&shash).unwrap();
        let (_st2, ch2) = begin_initiator(&chash, peer, 1_001).unwrap();
        assert_eq!(
            respond(&shash, &mut sreg, 1_001, &ch2).unwrap_err(),
            CryptoError::Authentication,
            "a revoked identity must be rejected (fail closed)"
        );

        // The initiator side can also revoke its peer: it then cannot even begin.
        creg.revoke(&shash);
        assert!(
            creg.lookup(&shash).is_none(),
            "revoked peer does not resolve"
        );

        // Re-instating clears the revocation.
        assert!(sreg.unrevoke(&chash));
        assert_eq!(sreg.revoked_count(), 0);
    }

    #[test]
    fn session_token_agrees_across_peers_and_rotates_by_epoch() {
        // Both peers hold the same auth_secret, so both derive the same token for
        // an epoch; different epochs give different tokens; comparison is CT.
        let (mut creg, mut sreg, chash, shash, _cm, _sm) = provision();
        let client_view = creg.lookup(&shash).unwrap().session_token(7);
        let server_view = sreg.lookup(&chash).unwrap().session_token(7);
        assert!(
            client_view.verify(&server_view),
            "both sides derive the same session token for the same epoch"
        );
        let next = creg.lookup(&shash).unwrap().session_token(8);
        assert!(
            !client_view.verify(&next),
            "rotating the epoch rotates the token"
        );
        // tokens are 32 bytes and non-trivial
        assert_eq!(client_view.as_bytes().len(), 32);
        assert_ne!(client_view.as_bytes(), &[0u8; 32]);
    }
}
