//! Air-gapped artifact signing & verification (CR-3 remediation).
//!
//! Internal Security Hardening and Pre-Audit Remediation.
//!
//! The pre-audit found that offline artifacts (identity exports, policy bundles)
//! were protected only by an **unkeyed SHA-256 stored inside the artifact** — an
//! active adversary on the sneakernet path can edit the artifact and recompute
//! the hash, defeating the integrity check (and, via peer-key substitution,
//! MITM-ing the whole overlay). This module replaces that with a **hybrid
//! Ed25519 + ML-DSA-65 signature** over a canonical manifest, verified against a
//! **pre-distributed trust anchor**, with fail-closed handling of:
//!   * missing signature, invalid signature (either algorithm failing),
//!   * unknown signer (not a trust anchor),
//!   * revoked signer,
//!   * replayed (stale-version) bundle.
//!
//! The SHA-256 of the payload is still carried for accidental-corruption
//! detection, but it is **never the security gate** — the signature is.

use std::collections::{HashMap, HashSet};

use sha2::{Digest, Sha256};

use crate::identity::{verify_hybrid, HybridSigner, IdentityError};

/// A signer is identified by the SHA-256 of its hybrid public keys (the same
/// construction as `IdentityKeyHash`), so a trust anchor is pinned to exact keys.
pub type SignerId = [u8; 32];

/// Compute a signer id from hybrid public keys.
pub fn signer_id(ed25519_pub: &[u8], mldsa65_pub: &[u8]) -> SignerId {
    let mut h = Sha256::new();
    h.update(b"syntriass-overlay airgap signer-id v1");
    h.update(ed25519_pub);
    h.update(mldsa65_pub);
    h.finalize().into()
}

/// Bundle kinds (domain-separated, so a policy bundle's signature can never be
/// replayed as an identity export and vice versa).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum BundleKind {
    IdentityExport,
    PolicyBundle,
    Package,
}

impl BundleKind {
    fn label(self) -> &'static [u8] {
        match self {
            BundleKind::IdentityExport => b"identity-export",
            BundleKind::PolicyBundle => b"policy-bundle",
            BundleKind::Package => b"package",
        }
    }
}

/// What is actually signed: a canonical, length-delimited encoding binding the
/// domain, kind, signer, monotonic version, and the payload. Any change to any
/// field invalidates the signature.
fn signed_message(kind: BundleKind, signer: &SignerId, version: u64, payload: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(64 + payload.len());
    m.extend_from_slice(b"syntriass-overlay airgap signed-bundle v1");
    m.extend_from_slice(kind.label());
    m.extend_from_slice(signer);
    m.extend_from_slice(&version.to_be_bytes());
    m.extend_from_slice(&(payload.len() as u64).to_be_bytes());
    m.extend_from_slice(payload);
    m
}

/// A signed, air-gap-transportable bundle.
#[derive(Clone, Debug)]
pub struct SignedBundle {
    pub kind: BundleKind,
    pub signer: SignerId,
    /// Monotonic version for replay protection (a verifier rejects a version it
    /// has already seen or that is below its floor).
    pub version: u64,
    pub payload: Vec<u8>,
    /// Accidental-corruption check only — NOT the security gate.
    pub payload_sha256: [u8; 32],
    pub ed25519_sig: [u8; 64],
    pub mldsa65_sig: Vec<u8>,
}

impl SignedBundle {
    /// Sign `payload` with a hybrid signer. `version` must increase across
    /// successive bundles of the same kind from the same signer.
    pub fn sign<S: HybridSigner>(
        kind: BundleKind,
        signer: &S,
        version: u64,
        payload: Vec<u8>,
    ) -> Result<Self, IdentityError> {
        let id = signer_id(&signer.ed25519_public(), &signer.mldsa65_public());
        let msg = signed_message(kind, &id, version, &payload);
        let (ed_sig, ml_sig) = signer.sign_hybrid(&msg)?;
        let mut h = Sha256::new();
        h.update(&payload);
        Ok(Self {
            kind,
            signer: id,
            version,
            payload,
            payload_sha256: h.finalize().into(),
            ed25519_sig: ed_sig,
            mldsa65_sig: ml_sig,
        })
    }
}

const BUNDLE_MAGIC: &[u8; 8] = b"SYNTABG1";

impl SignedBundle {
    /// Serialize to the on-disk / on-removable-media wire format. Length-delimited
    /// so a truncated or padded file is rejected by `from_bytes`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut o = Vec::with_capacity(128 + self.payload.len() + self.mldsa65_sig.len());
        o.extend_from_slice(BUNDLE_MAGIC);
        o.push(TrustStore::kind_byte(self.kind));
        o.extend_from_slice(&self.signer);
        o.extend_from_slice(&self.version.to_be_bytes());
        o.extend_from_slice(&self.payload_sha256);
        o.extend_from_slice(&self.ed25519_sig);
        o.extend_from_slice(&(self.mldsa65_sig.len() as u32).to_be_bytes());
        o.extend_from_slice(&self.mldsa65_sig);
        o.extend_from_slice(&(self.payload.len() as u64).to_be_bytes());
        o.extend_from_slice(&self.payload);
        o
    }

    /// Parse a bundle file. Fail-closed on any structural problem (wrong magic,
    /// short/over-long buffer, bad lengths) — these are *not* signature checks,
    /// they just guarantee a well-formed object to verify.
    pub fn from_bytes(buf: &[u8]) -> Result<Self, AirgapError> {
        let mut p = 0usize;
        let take = |p: &mut usize, n: usize| -> Result<&[u8], AirgapError> {
            let end = p.checked_add(n).ok_or(AirgapError::CorruptedPayload)?;
            if end > buf.len() {
                return Err(AirgapError::CorruptedPayload);
            }
            let s = &buf[*p..end];
            *p = end;
            Ok(s)
        };
        if take(&mut p, 8)? != BUNDLE_MAGIC {
            return Err(AirgapError::CorruptedPayload);
        }
        let kind = match take(&mut p, 1)?[0] {
            0 => BundleKind::IdentityExport,
            1 => BundleKind::PolicyBundle,
            2 => BundleKind::Package,
            _ => return Err(AirgapError::CorruptedPayload),
        };
        let mut signer = [0u8; 32];
        signer.copy_from_slice(take(&mut p, 32)?);
        let version = u64::from_be_bytes(take(&mut p, 8)?.try_into().unwrap());
        let mut payload_sha256 = [0u8; 32];
        payload_sha256.copy_from_slice(take(&mut p, 32)?);
        let mut ed25519_sig = [0u8; 64];
        ed25519_sig.copy_from_slice(take(&mut p, 64)?);
        let ml_len = u32::from_be_bytes(take(&mut p, 4)?.try_into().unwrap()) as usize;
        let mldsa65_sig = take(&mut p, ml_len)?.to_vec();
        let pl_len = u64::from_be_bytes(take(&mut p, 8)?.try_into().unwrap()) as usize;
        let payload = take(&mut p, pl_len)?.to_vec();
        if p != buf.len() {
            return Err(AirgapError::CorruptedPayload); // trailing garbage
        }
        Ok(Self {
            kind,
            signer,
            version,
            payload,
            payload_sha256,
            ed25519_sig,
            mldsa65_sig,
        })
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AirgapError {
    /// The signer is not a known trust anchor.
    UnknownSigner,
    /// The signer has been revoked.
    RevokedSigner,
    /// The hybrid signature did not verify (Ed25519 or ML-DSA failed).
    InvalidSignature,
    /// The bundle version is at or below the accepted floor (replay).
    ReplayedBundle,
    /// The carried payload hash does not match the payload (corrupted media);
    /// reported distinctly from a signature failure for operator diagnostics,
    /// but is still a hard reject.
    CorruptedPayload,
}

/// A signer's pinned public keys.
#[derive(Clone)]
struct Anchor {
    ed25519_pub: Vec<u8>,
    mldsa65_pub: Vec<u8>,
}

/// The verifier's trust state: pinned signer keys, a revocation set, and a
/// per-(kind,signer) version floor for replay protection.
#[derive(Default)]
pub struct TrustStore {
    anchors: HashMap<SignerId, Anchor>,
    revoked: HashSet<SignerId>,
    /// Highest accepted version per (kind, signer). A bundle must exceed it.
    version_floor: HashMap<(u8, SignerId), u64>,
}

impl TrustStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Pin a trust anchor (a signer the operator distributed out-of-band).
    pub fn add_anchor(&mut self, ed25519_pub: &[u8], mldsa65_pub: &[u8]) -> SignerId {
        let id = signer_id(ed25519_pub, mldsa65_pub);
        self.anchors.insert(
            id,
            Anchor {
                ed25519_pub: ed25519_pub.to_vec(),
                mldsa65_pub: mldsa65_pub.to_vec(),
            },
        );
        id
    }

    /// Revoke a signer (idempotent; a revoked anchor can never verify a bundle).
    pub fn revoke(&mut self, signer: &SignerId) {
        self.revoked.insert(*signer);
    }

    fn kind_byte(kind: BundleKind) -> u8 {
        match kind {
            BundleKind::IdentityExport => 0,
            BundleKind::PolicyBundle => 1,
            BundleKind::Package => 2,
        }
    }

    /// Verify a bundle WITHOUT consuming it (no version-floor advance). Fail
    /// closed on every error path.
    pub fn verify(&self, b: &SignedBundle) -> Result<(), AirgapError> {
        // 1) Revocation first — a revoked signer is rejected even if otherwise valid.
        if self.revoked.contains(&b.signer) {
            return Err(AirgapError::RevokedSigner);
        }
        // 2) Unknown signer -> reject (no trust anchor).
        let anchor = self
            .anchors
            .get(&b.signer)
            .ok_or(AirgapError::UnknownSigner)?;
        // 3) Replay: version must exceed the floor for this (kind, signer).
        let key = (Self::kind_byte(b.kind), b.signer);
        if let Some(floor) = self.version_floor.get(&key) {
            if b.version <= *floor {
                return Err(AirgapError::ReplayedBundle);
            }
        }
        // 4) Corruption check (diagnostic; still a hard reject).
        let mut h = Sha256::new();
        h.update(&b.payload);
        let digest: [u8; 32] = h.finalize().into();
        if digest != b.payload_sha256 {
            return Err(AirgapError::CorruptedPayload);
        }
        // 5) The security gate: hybrid signature over the canonical message,
        //    bound to the signer id the anchor pins (so substituting the signer
        //    field is caught — the message includes the id, and the id must map
        //    to these exact keys).
        let msg = signed_message(b.kind, &b.signer, b.version, &b.payload);
        verify_hybrid(
            &anchor.ed25519_pub,
            &anchor.mldsa65_pub,
            &msg,
            &b.ed25519_sig,
            &b.mldsa65_sig,
        )
        .map_err(|_| AirgapError::InvalidSignature)?;
        Ok(())
    }

    /// Verify AND advance the replay floor (consume). Use this on real
    /// application so a bundle cannot be replayed afterward.
    pub fn accept(&mut self, b: &SignedBundle) -> Result<(), AirgapError> {
        self.verify(b)?;
        let key = (Self::kind_byte(b.kind), b.signer);
        self.version_floor.insert(key, b.version);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::SoftwareSigner;

    fn signer() -> SoftwareSigner {
        SoftwareSigner::generate()
    }

    fn trust_for(s: &SoftwareSigner) -> TrustStore {
        let mut t = TrustStore::new();
        t.add_anchor(&s.ed25519_public(), &s.mldsa65_public());
        t
    }

    #[test]
    fn valid_bundle_verifies() {
        let s = signer();
        let t = trust_for(&s);
        let b = SignedBundle::sign(BundleKind::PolicyBundle, &s, 1, b"policy".to_vec()).unwrap();
        assert_eq!(t.verify(&b), Ok(()));
    }

    #[test]
    fn tampered_payload_is_rejected() {
        let s = signer();
        let t = trust_for(&s);
        let mut b =
            SignedBundle::sign(BundleKind::PolicyBundle, &s, 1, b"policy".to_vec()).unwrap();
        b.payload = b"evil".to_vec(); // edit content (and not the hash) -> corruption
        assert_eq!(t.verify(&b), Err(AirgapError::CorruptedPayload));
        // Edit content AND fix the hash (active adversary) -> signature now fails.
        let mut h = Sha256::new();
        h.update(&b.payload);
        b.payload_sha256 = h.finalize().into();
        assert_eq!(t.verify(&b), Err(AirgapError::InvalidSignature));
    }

    #[test]
    fn signer_substitution_is_rejected() {
        // Attacker signs with THEIR key and rewrites the signer id; the verifier
        // only trusts the pinned anchor, so the attacker's signer is unknown.
        let legit = signer();
        let attacker = signer();
        let t = trust_for(&legit);
        let evil = SignedBundle::sign(
            BundleKind::IdentityExport,
            &attacker,
            1,
            b"attacker-keys".to_vec(),
        )
        .unwrap();
        assert_eq!(t.verify(&evil), Err(AirgapError::UnknownSigner));
    }

    #[test]
    fn signer_id_forgery_is_rejected() {
        // Attacker keeps the legit signer id (to pass the anchor lookup) but signs
        // with their own key. The hybrid signature over the legit anchor's keys
        // then fails.
        let legit = signer();
        let attacker = signer();
        let t = trust_for(&legit);
        let legit_id = signer_id(&legit.ed25519_public(), &legit.mldsa65_public());
        let mut evil =
            SignedBundle::sign(BundleKind::PolicyBundle, &attacker, 1, b"x".to_vec()).unwrap();
        evil.signer = legit_id; // claim to be the legit signer
        assert_eq!(t.verify(&evil), Err(AirgapError::InvalidSignature));
    }

    #[test]
    fn replayed_bundle_is_rejected() {
        let s = signer();
        let mut t = trust_for(&s);
        let v1 = SignedBundle::sign(BundleKind::PolicyBundle, &s, 5, b"v5".to_vec()).unwrap();
        let v0 = SignedBundle::sign(BundleKind::PolicyBundle, &s, 3, b"v3".to_vec()).unwrap();
        assert_eq!(t.accept(&v1), Ok(())); // floor now 5
        assert_eq!(t.verify(&v0), Err(AirgapError::ReplayedBundle)); // older
        assert_eq!(t.verify(&v1), Err(AirgapError::ReplayedBundle)); // same version replay
    }

    #[test]
    fn corrupted_media_is_rejected() {
        let s = signer();
        let t = trust_for(&s);
        let mut b = SignedBundle::sign(BundleKind::Package, &s, 1, b"pkg".to_vec()).unwrap();
        // Flip a byte of the carried signature (corrupted media).
        b.ed25519_sig[0] ^= 0xFF;
        assert_eq!(t.verify(&b), Err(AirgapError::InvalidSignature));
    }

    #[test]
    fn revoked_signer_is_rejected() {
        let s = signer();
        let mut t = trust_for(&s);
        let b = SignedBundle::sign(BundleKind::PolicyBundle, &s, 1, b"p".to_vec()).unwrap();
        assert_eq!(t.verify(&b), Ok(()));
        t.revoke(&b.signer);
        assert_eq!(t.verify(&b), Err(AirgapError::RevokedSigner));
    }

    #[test]
    fn kind_confusion_is_rejected() {
        // A signature made for a policy bundle must not verify as an identity
        // export (domain separation by kind).
        let s = signer();
        let t = trust_for(&s);
        let mut b = SignedBundle::sign(BundleKind::PolicyBundle, &s, 1, b"p".to_vec()).unwrap();
        b.kind = BundleKind::IdentityExport;
        assert_eq!(t.verify(&b), Err(AirgapError::InvalidSignature));
    }
}
