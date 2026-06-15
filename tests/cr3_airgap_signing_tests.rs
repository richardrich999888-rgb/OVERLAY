//! CR-3 — Air-Gapped Integrity Protection: integration tests.
//!
//! Internal Security Hardening and Pre-Audit Remediation.
//!
//! Exercises the public air-gap signing API end-to-end, including the on-disk
//! bundle format (the artifact that crosses removable media). Required validation
//! scenarios: bundle tampering, signer substitution, replay, corrupted media,
//! revoked signer — each must fail closed.

use syntriass_overlay::airgap::{signer_id, AirgapError, BundleKind, SignedBundle, TrustStore};
use syntriass_overlay::identity::{HybridSigner, SoftwareSigner};

fn anchored() -> (SoftwareSigner, TrustStore) {
    let s = SoftwareSigner::generate();
    let mut t = TrustStore::new();
    t.add_anchor(&s.ed25519_public(), &s.mldsa65_public());
    (s, t)
}

#[test]
fn on_disk_roundtrip_verifies() {
    let (s, t) = anchored();
    let b = SignedBundle::sign(
        BundleKind::IdentityExport,
        &s,
        1,
        b"ed25519_public=...\nmldsa65_public=...".to_vec(),
    )
    .unwrap();
    let on_media = b.to_bytes(); // what travels on the USB stick
    let parsed = SignedBundle::from_bytes(&on_media).unwrap();
    assert_eq!(t.verify(&parsed), Ok(()));
}

#[test]
fn on_disk_tamper_is_rejected() {
    // Active adversary edits bytes of the bundle on the media.
    let (s, t) = anchored();
    let b = SignedBundle::sign(BundleKind::PolicyBundle, &s, 1, b"suite=nist768".to_vec()).unwrap();
    let mut media = b.to_bytes();
    // Flip a byte in the payload region (the tail of the buffer).
    let last = media.len() - 1;
    media[last] ^= 0xFF;
    let parsed = SignedBundle::from_bytes(&media).unwrap();
    // Hash no longer matches -> corruption; if an adversary also fixed the hash,
    // the signature fails (covered by the unit tests). Either way: hard reject.
    assert!(matches!(
        t.verify(&parsed),
        Err(AirgapError::CorruptedPayload) | Err(AirgapError::InvalidSignature)
    ));
}

#[test]
fn peer_key_substitution_mitm_is_blocked() {
    // The exact CR-3 attack: an adversary on the provisioning media substitutes
    // their OWN identity keys into an "identity export" and re-signs with their
    // own key. The importer trusts only the pre-distributed anchor, so the
    // attacker's signer is unknown and the import fails closed -> no MITM.
    let (_legit, t) = anchored();
    let attacker = SoftwareSigner::generate();
    let evil = SignedBundle::sign(
        BundleKind::IdentityExport,
        &attacker,
        1,
        b"attacker_ed=DEADBEEF\nattacker_ml=DEADBEEF".to_vec(),
    )
    .unwrap();
    let media = evil.to_bytes();
    let parsed = SignedBundle::from_bytes(&media).unwrap();
    assert_eq!(t.verify(&parsed), Err(AirgapError::UnknownSigner));
}

#[test]
fn replay_of_old_bundle_is_rejected() {
    let (s, mut t) = anchored();
    let new = SignedBundle::sign(BundleKind::PolicyBundle, &s, 10, b"policy-v10".to_vec()).unwrap();
    let old = SignedBundle::sign(BundleKind::PolicyBundle, &s, 4, b"policy-v4".to_vec()).unwrap();
    assert_eq!(t.accept(&new), Ok(())); // apply v10
                                        // Adversary replays the older signed bundle from captured media.
    let parsed = SignedBundle::from_bytes(&old.to_bytes()).unwrap();
    assert_eq!(t.verify(&parsed), Err(AirgapError::ReplayedBundle));
}

#[test]
fn revoked_signer_bundle_is_rejected() {
    let (s, mut t) = anchored();
    let b = SignedBundle::sign(BundleKind::PolicyBundle, &s, 1, b"p".to_vec()).unwrap();
    assert_eq!(t.verify(&b), Ok(()));
    let id = signer_id(&s.ed25519_public(), &s.mldsa65_public());
    t.revoke(&id);
    let parsed = SignedBundle::from_bytes(&b.to_bytes()).unwrap();
    assert_eq!(t.verify(&parsed), Err(AirgapError::RevokedSigner));
}

#[test]
fn truncated_media_is_rejected_structurally() {
    let (s, _t) = anchored();
    let b = SignedBundle::sign(BundleKind::Package, &s, 1, b"x".to_vec()).unwrap();
    let media = b.to_bytes();
    // Corrupted/truncated media: drop the last 10 bytes.
    let truncated = &media[..media.len() - 10];
    assert!(matches!(
        SignedBundle::from_bytes(truncated),
        Err(AirgapError::CorruptedPayload)
    ));
}
