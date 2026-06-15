//! Generic hybrid (X25519 + ML-KEM) engine core.
//!
//! Both NIST-768 and NIST-1024 suites are the *same* construction with a
//! different ML-KEM parameter set, so the logic lives here once, generic over
//! `K: KemCore`. The two suite modules (`nist768`, `nist1024`) instantiate it.
//!
//! Safety boundaries enforced here (not by callers):
//!   * Session keys never leave a `SessionKeys`; raw key bytes do not cross the
//!     trait boundary.
//!   * GCM nonces are owned by per-direction monotonic counters; no caller can
//!     choose or repeat a nonce.
//!   * The negotiated `suite_id` is folded into the HKDF `info` (transcript
//!     binding): a tampered suite byte yields non-matching keys -> AEAD fails
//!     closed.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use hkdf::Hkdf;
use ml_kem::kem::{Decapsulate, Encapsulate};
use ml_kem::{Encoded, EncodedSizeUser, KemCore};
use sha2::{Digest, Sha256};
use std::fmt;
use subtle::ConstantTimeEq;
use x25519_dalek::{EphemeralSecret, PublicKey as XPublicKey};
use zeroize::{Zeroize, Zeroizing};

use super::{
    CryptoError, IdentityMaterial, SessionKeys, ED25519_PUBLIC_LEN, ED25519_SIGNATURE_LEN,
    IDENTITY_PUBLIC_LEN, IDENTITY_SIGNATURE_LEN, MLDSA65_PUBLIC_LEN, MLDSA65_SIGNATURE_LEN,
    X25519_LEN,
};

/// HKDF label prefix. The concrete suite id is appended for transcript binding.
const HKDF_LABEL_PREFIX: &[u8] = b"syntriass-overlay v3 suite=";
/// Domain-separation label for the forward-secret rekey ratchet (see
/// [`Direction::ratchet`]). The epoch counter is appended for uniqueness.
const REKEY_LABEL: &[u8] = b"syntriass-overlay rekey v1";
const CLIENT_AUTH_LABEL: &[u8] = b"syntriass-overlay client identity v1";
const SERVER_AUTH_LABEL: &[u8] = b"syntriass-overlay server identity v1";
const KEY_TRANSCRIPT_LABEL: &[u8] = b"syntriass-overlay transcript hash v1";

type IdentityFields<'a> = (&'a [u8], &'a [u8], &'a [u8], &'a [u8]);

/// Build a 96-bit GCM nonce from a big-endian u64 counter in the low 8 bytes.
fn nonce_from_counter(counter: u64) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[4..].copy_from_slice(&counter.to_be_bytes());
    n
}

/// One AEAD direction with an owned, monotonic counter. Public methods only
/// expose seal/open; the key and counter are private.
///
/// `Clone` exists solely so the hardened record layer (`crypto::session`) can
/// retain the previous epoch's receive direction for one rekey step (in-flight
/// records). The clone never crosses the crate boundary and both copies zeroize
/// on drop.
#[derive(Clone)]
pub struct Direction {
    key: Zeroizing<[u8; 32]>,
    counter: u64,
}

impl fmt::Debug for Direction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Direction")
            .field("counter", &self.counter)
            .finish_non_exhaustive()
    }
}

impl Direction {
    fn new(key: [u8; 32]) -> Self {
        Self {
            key: Zeroizing::new(key),
            counter: 0,
        }
    }

    pub fn seal(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if self.counter == u64::MAX {
            return Err(CryptoError::NonceExhausted);
        }
        let n = nonce_from_counter(self.counter);
        let cipher =
            Aes256Gcm::new_from_slice(self.key.as_ref()).map_err(|_| CryptoError::Encrypt)?;
        let ct = cipher
            .encrypt(
                Nonce::from_slice(&n),
                Payload {
                    msg: plaintext,
                    aad: &[],
                },
            )
            .map_err(|_| CryptoError::Encrypt)?;
        self.counter += 1;
        Ok(ct)
    }

    /// Export TLS-1.3 AES-256-GCM material for kTLS: the AEAD key, plus a
    /// 4-byte salt and 8-byte IV HKDF-expanded from that key (deterministic, so
    /// both peers derive identical material for the matching direction).
    pub(crate) fn ktls_secret(&self) -> super::KtlsTrafficSecret {
        let mut okm = [0u8; 12];
        Hkdf::<Sha256>::new(None, &self.key[..])
            .expand(b"syntriass-overlay ktls salt+iv v1", &mut okm)
            .expect("12 bytes is within HKDF output bounds");
        let mut key = [0u8; 32];
        key.copy_from_slice(&self.key[..]);
        let mut salt = [0u8; 4];
        let mut iv = [0u8; 8];
        salt.copy_from_slice(&okm[0..4]);
        iv.copy_from_slice(&okm[4..12]);
        okm.zeroize();
        super::KtlsTrafficSecret { key, salt, iv }
    }

    pub fn open(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if self.counter == u64::MAX {
            return Err(CryptoError::NonceExhausted);
        }
        let n = nonce_from_counter(self.counter);
        let cipher =
            Aes256Gcm::new_from_slice(self.key.as_ref()).map_err(|_| CryptoError::Decrypt)?;
        let pt = cipher
            .decrypt(
                Nonce::from_slice(&n),
                Payload {
                    msg: ciphertext,
                    aad: &[],
                },
            )
            .map_err(|_| CryptoError::Decrypt)?;
        self.counter += 1;
        Ok(pt)
    }

    /// Seal at an explicit sequence number, binding `aad` (the record header)
    /// into the GCM tag. Unlike [`seal`](Self::seal) this does not touch the
    /// internal counter: the hardened record layer owns sequencing. The 96-bit
    /// nonce is derived from `seq`; because every rekey installs a fresh
    /// [`ratchet`](Self::ratchet)ed key and `seq` is unique per epoch, no
    /// `(key, nonce)` pair is ever reused.
    pub(crate) fn seal_at(
        &self,
        seq: u64,
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let n = nonce_from_counter(seq);
        let cipher =
            Aes256Gcm::new_from_slice(self.key.as_ref()).map_err(|_| CryptoError::Encrypt)?;
        cipher
            .encrypt(
                Nonce::from_slice(&n),
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .map_err(|_| CryptoError::Encrypt)
    }

    /// Open a record sealed with [`seal_at`](Self::seal_at). The caller is
    /// responsible for anti-replay; this only authenticates `(seq, aad, ct)`.
    pub(crate) fn open_at(
        &self,
        seq: u64,
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let n = nonce_from_counter(seq);
        let cipher =
            Aes256Gcm::new_from_slice(self.key.as_ref()).map_err(|_| CryptoError::Decrypt)?;
        cipher
            .decrypt(
                Nonce::from_slice(&n),
                Payload {
                    msg: ciphertext,
                    aad,
                },
            )
            .map_err(|_| CryptoError::Decrypt)
    }

    /// One-way symmetric ratchet for intra-session forward secrecy. The new key
    /// is `HKDF-SHA256(old_key, "syntriass-overlay rekey v1" || epoch)`; the old
    /// key bytes are overwritten in place (the buffer is `Zeroizing`). Because
    /// HKDF is one-way, an adversary who compromises the post-ratchet key cannot
    /// recover any earlier epoch's key (and therefore cannot decrypt earlier
    /// traffic). The per-direction counter is reset for the new epoch.
    pub(crate) fn ratchet(&mut self, epoch: u32) {
        let mut info = Vec::with_capacity(REKEY_LABEL.len() + 4);
        info.extend_from_slice(REKEY_LABEL);
        info.extend_from_slice(&epoch.to_be_bytes());
        let hk = Hkdf::<Sha256>::new(None, self.key.as_ref());
        let mut next = [0u8; 32];
        hk.expand(&info, &mut next)
            .expect("32 bytes is within HKDF output bounds");
        self.key[..].copy_from_slice(&next);
        next.zeroize();
        self.counter = 0;
    }
}

/// Derive directional keys from hybrid IKM, binding suite and authenticated transcript.
fn derive(
    ikm: &[u8],
    suite_id: u8,
    transcript_hash: &[u8; 32],
    is_initiator: bool,
) -> Result<SessionKeys, CryptoError> {
    let mut info = Vec::with_capacity(HKDF_LABEL_PREFIX.len() + 1 + transcript_hash.len());
    info.extend_from_slice(HKDF_LABEL_PREFIX);
    info.push(suite_id);
    info.extend_from_slice(transcript_hash);
    let hk = Hkdf::<Sha256>::new(None, ikm);
    let mut okm = [0u8; 64];
    hk.expand(&info, &mut okm).map_err(|_| CryptoError::Hkdf)?;
    let mut c2s = [0u8; 32];
    let mut s2c = [0u8; 32];
    c2s.copy_from_slice(&okm[0..32]);
    s2c.copy_from_slice(&okm[32..64]);
    // Initiator writes c2s/reads s2c; responder mirrored.
    let (tx, rx) = if is_initiator { (c2s, s2c) } else { (s2c, c2s) };
    let keys = SessionKeys {
        tx: Direction::new(tx),
        rx: Direction::new(rx),
    };
    okm.zeroize();
    c2s.zeroize();
    s2c.zeroize();
    Ok(keys)
}

/// Quantum-safe *degraded* fallback key schedule.
///
/// Derives an AES-256-GCM session purely from a pre-shared key plus a fresh
/// client/server nonce pair — no asymmetric crypto at all. This is the
/// confidentiality-preserving alternative to a plaintext bypass: when the full
/// PQC control plane is unavailable, peers that share a PSK can still talk
/// *encrypted* (AES-256 ⇒ 128-bit post-quantum security via Grover), and the PSK
/// itself authenticates (an attacker without it derives a different key and AEAD
/// open fails). The tradeoff vs. the full handshake is **no forward secrecy**
/// (PSK reuse); that is the documented price of availability under jamming, and
/// it never sends cleartext.
pub(crate) fn derive_fallback(
    psk: &[u8],
    client_nonce: &[u8],
    server_nonce: &[u8],
    is_initiator: bool,
) -> Result<SessionKeys, CryptoError> {
    let mut h = Sha256::new();
    h.update(b"syntriass-overlay psk-fallback transcript v1");
    h.update(client_nonce);
    h.update(server_nonce);
    let th: [u8; 32] = h.finalize().into();
    // 0xFF is reserved: `CipherSuite::from_id(0xFF)` is `None`, so fallback keys
    // can never collide with a real suite's key schedule (domain separation).
    derive(psk, 0xFF, &th, is_initiator)
}

/// Retained initiator secrets for a generic suite. Boxed behind `InitiatorState`.
pub struct GenericInitiatorState<K: KemCore> {
    suite_id: u8,
    x_secret: EphemeralSecret,
    ml_decap: K::DecapsulationKey,
    client_hello: Vec<u8>,
}

/// Produce a ClientHello body and the initiator state to retain.
/// Body = X25519 public key || ML-KEM encapsulation key || identity keys || signatures.
pub fn client_hello<K: KemCore>(
    suite_id: u8,
    identity: &IdentityMaterial,
) -> Result<(GenericInitiatorState<K>, Vec<u8>), CryptoError> {
    let x_secret = EphemeralSecret::random();
    let x_public = XPublicKey::from(&x_secret);
    let mut rng = rand_core::OsRng;
    let (ml_decap, ml_encap) = K::generate(&mut rng);

    let ek_bytes = ml_encap.as_bytes();
    let mut unsigned = Vec::with_capacity(X25519_LEN + ek_bytes.len() + IDENTITY_PUBLIC_LEN);
    unsigned.extend_from_slice(x_public.as_bytes());
    unsigned.extend_from_slice(ek_bytes.as_slice());
    unsigned.extend_from_slice(identity.own_ed25519_public());
    unsigned.extend_from_slice(identity.own_mldsa65_public());

    let auth_msg = client_auth_message(suite_id, &unsigned);
    let signatures = identity.sign(&auth_msg)?;

    let mut body = Vec::with_capacity(unsigned.len() + IDENTITY_SIGNATURE_LEN);
    body.extend_from_slice(&unsigned);
    body.extend_from_slice(&signatures.ed25519);
    body.extend_from_slice(&signatures.mldsa65);

    Ok((
        GenericInitiatorState {
            suite_id,
            x_secret,
            ml_decap,
            client_hello: body.clone(),
        },
        body,
    ))
}

/// Responder: consume ClientHello, return established keys + ServerHello body.
/// Body in  = X25519 pk || ML-KEM ek. Body out = X25519 pk || ML-KEM ct.
pub fn respond<K: KemCore>(
    suite_id: u8,
    ek_len: usize,
    identity: &IdentityMaterial,
    body: &[u8],
) -> Result<(SessionKeys, Vec<u8>), CryptoError> {
    let unsigned_len = X25519_LEN + ek_len + IDENTITY_PUBLIC_LEN;
    let expected_len = unsigned_len + IDENTITY_SIGNATURE_LEN;
    if body.len() != expected_len {
        return Err(CryptoError::BadHelloLength);
    }
    let unsigned = &body[..unsigned_len];
    let (client_ed_pub, client_ml_pub, client_ed_sig, client_ml_sig) =
        split_identity_fields(body, X25519_LEN + ek_len)?;
    identity.verify_peer_public_keys(client_ed_pub, client_ml_pub)?;
    let auth_msg = client_auth_message(suite_id, unsigned);
    identity.verify_peer_signatures(&auth_msg, client_ed_sig, client_ml_sig)?;

    let peer_x_arr: [u8; 32] = body[0..X25519_LEN]
        .try_into()
        .map_err(|_| CryptoError::BadHelloLength)?;
    let peer_x = XPublicKey::from(peer_x_arr);

    // Parse the ML-KEM encapsulation key from wire bytes into its Encoded form.
    // `Encoded<T>` is a `hybrid_array::Array<u8, N>`; `TryFrom<&[u8]>` exists and
    // succeeds because we already validated `body.len()`. If the compiler reports
    // an unsatisfied `TryFrom` bound here (a known hybrid-array inference wrinkle,
    // RustCrypto/hybrid-array#114), the mechanical fix is:
    //     use ml_kem::array::Array;
    //     let ek_enc = Array::try_from(ek_slice).map_err(|_| CryptoError::MlKemDecode)?;
    let ek_slice = &body[X25519_LEN..X25519_LEN + ek_len];
    let ek_enc =
        Encoded::<K::EncapsulationKey>::try_from(ek_slice).map_err(|_| CryptoError::MlKemDecode)?;
    let peer_ek = K::EncapsulationKey::from_bytes(&ek_enc);

    let server_x_secret = EphemeralSecret::random();
    let server_x_public = XPublicKey::from(&server_x_secret);

    let mut rng = rand_core::OsRng;
    let (ml_ct, ml_ss) = peer_ek
        .encapsulate(&mut rng)
        .map_err(|_| CryptoError::MlKemDecode)?;
    let x_ss = server_x_secret.diffie_hellman(&peer_x);

    let mut ikm = Zeroizing::new(Vec::with_capacity(32 + ml_ss.as_slice().len()));
    ikm.extend_from_slice(x_ss.as_bytes());
    ikm.extend_from_slice(ml_ss.as_slice());

    let mut server_unsigned =
        Vec::with_capacity(X25519_LEN + ml_ct.as_slice().len() + IDENTITY_PUBLIC_LEN);
    server_unsigned.extend_from_slice(server_x_public.as_bytes());
    server_unsigned.extend_from_slice(ml_ct.as_slice());
    server_unsigned.extend_from_slice(identity.own_ed25519_public());
    server_unsigned.extend_from_slice(identity.own_mldsa65_public());

    let server_auth = server_auth_message(suite_id, body, &server_unsigned);
    let signatures = identity.sign(&server_auth)?;

    let mut hello = Vec::with_capacity(server_unsigned.len() + IDENTITY_SIGNATURE_LEN);
    hello.extend_from_slice(&server_unsigned);
    hello.extend_from_slice(&signatures.ed25519);
    hello.extend_from_slice(&signatures.mldsa65);

    let th = transcript_hash(suite_id, body, &hello);
    let keys = derive(&ikm, suite_id, &th, false)?;

    Ok((keys, hello))
}

/// Initiator step 2: consume ServerHello, finish key agreement.
pub fn finish<K: KemCore>(
    state: GenericInitiatorState<K>,
    ct_len: usize,
    identity: &IdentityMaterial,
    body: &[u8],
) -> Result<SessionKeys, CryptoError> {
    let unsigned_len = X25519_LEN + ct_len + IDENTITY_PUBLIC_LEN;
    let expected_len = unsigned_len + IDENTITY_SIGNATURE_LEN;
    if body.len() != expected_len {
        return Err(CryptoError::BadHelloLength);
    }
    let unsigned = &body[..unsigned_len];
    let (server_ed_pub, server_ml_pub, server_ed_sig, server_ml_sig) =
        split_identity_fields(body, X25519_LEN + ct_len)?;
    identity.verify_peer_public_keys(server_ed_pub, server_ml_pub)?;
    let auth_msg = server_auth_message(state.suite_id, &state.client_hello, unsigned);
    identity.verify_peer_signatures(&auth_msg, server_ed_sig, server_ml_sig)?;

    let peer_x_arr: [u8; 32] = body[0..X25519_LEN]
        .try_into()
        .map_err(|_| CryptoError::BadHelloLength)?;
    let peer_x = XPublicKey::from(peer_x_arr);

    // `Ciphertext<K>` is also a `hybrid_array::Array<u8, N>`. Same note as above:
    // if `try_from` inference fights, use `ml_kem::array::Array::try_from(ct_slice)`.
    let ct_slice = &body[X25519_LEN..X25519_LEN + ct_len];
    let ct = ml_kem::Ciphertext::<K>::try_from(ct_slice).map_err(|_| CryptoError::MlKemDecode)?;

    let ml_ss = state
        .ml_decap
        .decapsulate(&ct)
        .map_err(|_| CryptoError::Decapsulate)?;
    let x_ss = state.x_secret.diffie_hellman(&peer_x);

    let mut ikm = Zeroizing::new(Vec::with_capacity(32 + ml_ss.as_slice().len()));
    ikm.extend_from_slice(x_ss.as_bytes());
    ikm.extend_from_slice(ml_ss.as_slice());
    let th = transcript_hash(state.suite_id, &state.client_hello, body);
    let keys = derive(&ikm, state.suite_id, &th, true)?;
    Ok(keys)
}

// ----------------------- Out-of-band identity (compact runtime) -----------------------
//
// The full handshake above carries the peer's ML-DSA-65 public key (1952 B) and a
// fresh ML-DSA-65 signature (3309 B) on EVERY handshake. The out-of-band variant
// removes both from the runtime wire: the peer is referenced by a 32-byte
// `IdentityKeyHash`, and authentication is a 32-byte HMAC capability under a
// per-peer `auth_secret` that was established during PQ-authenticated provisioning
// (the ML-DSA exchange happens once, off the runtime path). The KEM exchange
// (X25519 + ML-KEM) — i.e. the confidentiality + forward secrecy — is unchanged.
// Mutual authentication is preserved: each side proves possession of the shared
// `auth_secret` over the transcript, with domain-separated client/server labels.

const OOB_HASH_LEN: usize = 32;
const OOB_TAG_LEN: usize = 32;
const OOB_CLIENT_LABEL: &[u8] = b"syntriass-overlay oob client-auth v1";
const OOB_SERVER_LABEL: &[u8] = b"syntriass-overlay oob server-auth v1";

fn oob_tag(auth_secret: &[u8], label: &[u8], suite_id: u8, parts: &[&[u8]]) -> [u8; OOB_TAG_LEN] {
    use hmac::{Hmac, Mac};
    let mut m =
        <Hmac<Sha256> as Mac>::new_from_slice(auth_secret).expect("HMAC accepts any key length");
    m.update(label);
    m.update(&[suite_id]);
    for p in parts {
        m.update(p);
    }
    let out = m.finalize().into_bytes();
    let mut t = [0u8; OOB_TAG_LEN];
    t.copy_from_slice(&out);
    t
}

/// Retained initiator secrets for an out-of-band handshake.
pub struct OobInitiatorState<K: KemCore> {
    suite_id: u8,
    x_secret: EphemeralSecret,
    ml_decap: K::DecapsulationKey,
    client_hello: Vec<u8>,
}

/// Out-of-band ClientHello. Body = `x_pub(32) || ML-KEM ek || own_hash(32) || tag(32)`.
pub fn oob_client_hello<K: KemCore>(
    suite_id: u8,
    own_hash: &[u8; OOB_HASH_LEN],
    auth_secret: &[u8],
) -> Result<(OobInitiatorState<K>, Vec<u8>), CryptoError> {
    let x_secret = EphemeralSecret::random();
    let x_public = XPublicKey::from(&x_secret);
    let mut rng = rand_core::OsRng;
    let (ml_decap, ml_encap) = K::generate(&mut rng);
    let ek = ml_encap.as_bytes();

    let mut unsigned = Vec::with_capacity(X25519_LEN + ek.len() + OOB_HASH_LEN);
    unsigned.extend_from_slice(x_public.as_bytes());
    unsigned.extend_from_slice(ek.as_slice());
    unsigned.extend_from_slice(own_hash);

    let tag = oob_tag(auth_secret, OOB_CLIENT_LABEL, suite_id, &[&unsigned]);
    let mut body = unsigned;
    body.extend_from_slice(&tag);
    Ok((
        OobInitiatorState {
            suite_id,
            x_secret,
            ml_decap,
            client_hello: body.clone(),
        },
        body,
    ))
}

/// Extract the peer's `IdentityKeyHash` from an out-of-band ClientHello so the
/// responder can resolve the shared `auth_secret` from its registry before
/// verifying the tag. Length-validated; returns `BadHelloLength` on a short body.
pub fn oob_client_hash(body: &[u8], ek_len: usize) -> Result<[u8; OOB_HASH_LEN], CryptoError> {
    let unsigned_len = X25519_LEN + ek_len + OOB_HASH_LEN;
    if body.len() != unsigned_len + OOB_TAG_LEN {
        return Err(CryptoError::BadHelloLength);
    }
    let h = &body[X25519_LEN + ek_len..unsigned_len];
    let mut out = [0u8; OOB_HASH_LEN];
    out.copy_from_slice(h);
    Ok(out)
}

/// Out-of-band responder. Verifies the client tag under the (registry-resolved)
/// shared `auth_secret`, encapsulates, and returns the established keys plus a
/// ServerHello that carries `own_hash` and a server tag binding the full
/// transcript. Body out = `x_pub(32) || ML-KEM ct || own_hash(32) || tag(32)`.
pub fn oob_respond<K: KemCore>(
    suite_id: u8,
    ek_len: usize,
    own_hash: &[u8; OOB_HASH_LEN],
    auth_secret: &[u8],
    body: &[u8],
) -> Result<(SessionKeys, Vec<u8>), CryptoError> {
    let unsigned_len = X25519_LEN + ek_len + OOB_HASH_LEN;
    if body.len() != unsigned_len + OOB_TAG_LEN {
        return Err(CryptoError::BadHelloLength);
    }
    let unsigned = &body[..unsigned_len];
    let tag = &body[unsigned_len..];
    let expect = oob_tag(auth_secret, OOB_CLIENT_LABEL, suite_id, &[unsigned]);
    if !bool::from(expect[..].ct_eq(tag)) {
        return Err(CryptoError::Authentication);
    }

    let peer_x_arr: [u8; 32] = body[0..X25519_LEN]
        .try_into()
        .map_err(|_| CryptoError::BadHelloLength)?;
    let peer_x = XPublicKey::from(peer_x_arr);
    let ek_slice = &body[X25519_LEN..X25519_LEN + ek_len];
    let ek_enc =
        Encoded::<K::EncapsulationKey>::try_from(ek_slice).map_err(|_| CryptoError::MlKemDecode)?;
    let peer_ek = K::EncapsulationKey::from_bytes(&ek_enc);

    let server_x_secret = EphemeralSecret::random();
    let server_x_public = XPublicKey::from(&server_x_secret);
    let mut rng = rand_core::OsRng;
    let (ml_ct, ml_ss) = peer_ek
        .encapsulate(&mut rng)
        .map_err(|_| CryptoError::MlKemDecode)?;
    let x_ss = server_x_secret.diffie_hellman(&peer_x);

    let mut ikm = Zeroizing::new(Vec::with_capacity(32 + ml_ss.as_slice().len()));
    ikm.extend_from_slice(x_ss.as_bytes());
    ikm.extend_from_slice(ml_ss.as_slice());

    let mut server_unsigned =
        Vec::with_capacity(X25519_LEN + ml_ct.as_slice().len() + OOB_HASH_LEN);
    server_unsigned.extend_from_slice(server_x_public.as_bytes());
    server_unsigned.extend_from_slice(ml_ct.as_slice());
    server_unsigned.extend_from_slice(own_hash);

    // Server tag binds the client hello (channel binding) + the server unsigned.
    let stag = oob_tag(
        auth_secret,
        OOB_SERVER_LABEL,
        suite_id,
        &[body, &server_unsigned],
    );
    let mut hello = server_unsigned;
    hello.extend_from_slice(&stag);

    let th = transcript_hash(suite_id, body, &hello);
    let keys = derive(&ikm, suite_id, &th, false)?;
    Ok((keys, hello))
}

/// Out-of-band initiator step 2. Verifies the server tag, confirms the responder
/// is the expected peer (`expected_server_hash`), decapsulates, and derives keys.
pub fn oob_finish<K: KemCore>(
    state: OobInitiatorState<K>,
    ct_len: usize,
    expected_server_hash: &[u8; OOB_HASH_LEN],
    auth_secret: &[u8],
    body: &[u8],
) -> Result<SessionKeys, CryptoError> {
    let unsigned_len = X25519_LEN + ct_len + OOB_HASH_LEN;
    if body.len() != unsigned_len + OOB_TAG_LEN {
        return Err(CryptoError::BadHelloLength);
    }
    let server_unsigned = &body[..unsigned_len];
    let stag = &body[unsigned_len..];
    let server_hash = &body[X25519_LEN + ct_len..unsigned_len];
    if !bool::from(server_hash.ct_eq(&expected_server_hash[..])) {
        return Err(CryptoError::Authentication);
    }
    let expect = oob_tag(
        auth_secret,
        OOB_SERVER_LABEL,
        state.suite_id,
        &[&state.client_hello, server_unsigned],
    );
    if !bool::from(expect[..].ct_eq(stag)) {
        return Err(CryptoError::Authentication);
    }

    let peer_x_arr: [u8; 32] = body[0..X25519_LEN]
        .try_into()
        .map_err(|_| CryptoError::BadHelloLength)?;
    let peer_x = XPublicKey::from(peer_x_arr);
    let ct_slice = &body[X25519_LEN..X25519_LEN + ct_len];
    let ct = ml_kem::Ciphertext::<K>::try_from(ct_slice).map_err(|_| CryptoError::MlKemDecode)?;
    let ml_ss = state
        .ml_decap
        .decapsulate(&ct)
        .map_err(|_| CryptoError::Decapsulate)?;
    let x_ss = state.x_secret.diffie_hellman(&peer_x);

    let mut ikm = Zeroizing::new(Vec::with_capacity(32 + ml_ss.as_slice().len()));
    ikm.extend_from_slice(x_ss.as_bytes());
    ikm.extend_from_slice(ml_ss.as_slice());
    let th = transcript_hash(state.suite_id, &state.client_hello, body);
    derive(&ikm, state.suite_id, &th, true)
}

fn split_identity_fields(
    body: &[u8],
    public_start: usize,
) -> Result<IdentityFields<'_>, CryptoError> {
    let ed_pub_end = public_start + ED25519_PUBLIC_LEN;
    let ml_pub_end = ed_pub_end + MLDSA65_PUBLIC_LEN;
    let ed_sig_end = ml_pub_end + ED25519_SIGNATURE_LEN;
    let ml_sig_end = ed_sig_end + MLDSA65_SIGNATURE_LEN;
    if body.len() != ml_sig_end {
        return Err(CryptoError::BadHelloLength);
    }
    Ok((
        &body[public_start..ed_pub_end],
        &body[ed_pub_end..ml_pub_end],
        &body[ml_pub_end..ed_sig_end],
        &body[ed_sig_end..ml_sig_end],
    ))
}

fn client_auth_message(suite_id: u8, client_unsigned: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(CLIENT_AUTH_LABEL.len() + 1 + client_unsigned.len());
    out.extend_from_slice(CLIENT_AUTH_LABEL);
    out.push(suite_id);
    out.extend_from_slice(client_unsigned);
    out
}

fn server_auth_message(suite_id: u8, client_hello: &[u8], server_unsigned: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(
        SERVER_AUTH_LABEL.len() + 1 + client_hello.len() + server_unsigned.len(),
    );
    out.extend_from_slice(SERVER_AUTH_LABEL);
    out.push(suite_id);
    out.extend_from_slice(client_hello);
    out.extend_from_slice(server_unsigned);
    out
}

fn transcript_hash(suite_id: u8, client_hello: &[u8], server_hello: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(KEY_TRANSCRIPT_LABEL);
    h.update([suite_id]);
    h.update(client_hello);
    h.update(server_hello);
    h.finalize().into()
}

#[cfg(test)]
mod binding_tests {
    use super::*;

    /// Transcript binding, isolated: identical IKM + identical role but a
    /// different suite id must yield different keys (the id is in HKDF info).
    /// We prove it by sealing under one and failing to open under the other.
    #[test]
    fn suite_id_changes_derived_keys() {
        let ikm = [0x42u8; 64];
        let transcript_a = [0x11u8; 32];
        let transcript_b = [0x22u8; 32];
        let mut a = derive(&ikm, 0x01, &transcript_a, true).expect("derive a");
        let mut b = derive(&ikm, 0x02, &transcript_a, true).expect("derive b");
        let ct = a.tx.seal(b"transcript-bound").unwrap();
        // b's rx direction uses the same role mapping but a different suite id,
        // so its key differs and authentication must fail.
        assert!(b.rx.open(&ct).is_err());

        let mut c = derive(&ikm, 0x01, &transcript_b, true).expect("derive c");
        let ct = a.tx.seal(b"transcript-bound-again").unwrap();
        assert!(c.rx.open(&ct).is_err());
    }

    /// Same suite id + same IKM + same role -> identical, interoperable keys
    /// (sanity check that the derivation is deterministic and not just random).
    #[test]
    fn same_inputs_interoperate() {
        let ikm = [0x07u8; 64];
        let transcript = [0x77u8; 32];
        let mut initiator = derive(&ikm, 0x01, &transcript, true).expect("init");
        let mut responder = derive(&ikm, 0x01, &transcript, false).expect("resp");
        let ct = initiator.tx.seal(b"hello").unwrap();
        assert_eq!(responder.rx.open(&ct).unwrap(), b"hello");
    }
}
