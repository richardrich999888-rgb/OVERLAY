//! External-backend keystore validation (TPM / PKCS#11 / HSM).
//!
//! These are `#[ignore]`d by default because they require a running token: a
//! software TPM (`swtpm`) or a PKCS#11 module (SoftHSM2). They exercise the
//! **real** `ExternalKeyProtector` → `CommandSealer` → vendor-tooling path used
//! in deployment. `scripts/keystore/validate.sh` sets up the substitute token
//! and runs these with `--ignored`. A physical-device acceptance test is still
//! required (documented in `docs/{TPM,HSM}_INTEGRATION.md`); these prove the
//! adapter against the standard software substitutes.
//!
//! Drive with, e.g.:
//!   SYNTRIASS_TPM_SEAL=scripts/keystore/tpm_seal.sh \
//!   SYNTRIASS_TPM_UNSEAL=scripts/keystore/tpm_unseal.sh \
//!   TPM2TOOLS_TCTI=swtpm:... \
//!   cargo test --test keystore_external_tests -- --ignored --nocapture

#![cfg(target_os = "linux")]

use syntriass_overlay::identity::{HybridSigner, SoftwareSigner};
use syntriass_overlay::keystore::{Backend, CommandSealer, ExternalKeyProtector, SealedKeystore};

/// Seal the hybrid identity seeds through an external token, transport the sealed
/// keystore as bytes, then unseal and confirm the reconstructed signer's public
/// keys match — i.e. the token protected the keys at rest and released them only
/// on unlock.
fn run_external_backend(backend: Backend, seal: &str, unseal: &str) {
    let sealer = CommandSealer {
        seal_argv: vec![seal.to_string()],
        unseal_argv: vec![unseal.to_string()],
    };
    let protector = ExternalKeyProtector::new(backend, sealer);

    let (ed, ml) = ([0x11u8; 32], [0x22u8; 32]);
    let reference = SoftwareSigner::from_seeds(ed, ml).unwrap();

    let ks = SealedKeystore::seal(&protector, [0x33; 16], &ed, &ml)
        .expect("seal hybrid seeds to the token");
    // Air-gap transport round-trip.
    let ks2 = SealedKeystore::from_bytes(&ks.to_bytes()).expect("keystore re-parse");
    assert_eq!(ks2.backend, backend);

    let signer = ks2
        .unlock_signer(&protector)
        .expect("unseal + rebuild signer");
    assert_eq!(
        signer.ed25519_public(),
        reference.ed25519_public(),
        "Ed25519 public key must survive seal→transport→unseal"
    );
    assert_eq!(
        signer.mldsa65_public(),
        reference.mldsa65_public(),
        "ML-DSA-65 public key must survive seal→transport→unseal"
    );
    eprintln!(
        "[{backend:?} keystore] sealed + transported + unsealed both hybrid seeds; signer reconstructed"
    );
}

#[test]
#[ignore = "requires swtpm + TPM2TOOLS_TCTI + SYNTRIASS_TPM_SEAL/UNSEAL (see scripts/keystore/validate.sh)"]
fn tpm_backed_keystore_seals_and_unlocks_the_signer() {
    let seal = std::env::var("SYNTRIASS_TPM_SEAL").expect("SYNTRIASS_TPM_SEAL");
    let unseal = std::env::var("SYNTRIASS_TPM_UNSEAL").expect("SYNTRIASS_TPM_UNSEAL");
    run_external_backend(Backend::Tpm2, &seal, &unseal);
}

#[test]
#[ignore = "requires SoftHSM2 + SYNTRIASS_PKCS11_SEAL/UNSEAL (see scripts/keystore/validate.sh)"]
fn pkcs11_backed_keystore_seals_and_unlocks_the_signer() {
    let seal = std::env::var("SYNTRIASS_PKCS11_SEAL").expect("SYNTRIASS_PKCS11_SEAL");
    let unseal = std::env::var("SYNTRIASS_PKCS11_UNSEAL").expect("SYNTRIASS_PKCS11_UNSEAL");
    run_external_backend(Backend::Pkcs11, &seal, &unseal);
}
