//! Sovereign key storage — a backend-agnostic key-protection abstraction.
//!
//! This replaces the "raw seed bytes in a file / env var" assumption with sealed
//! key material: a long-term seed is **sealed** (encrypted) under a key held by a
//! protection backend, and only **unsealed** with that backend present. The
//! backend may be:
//!
//!   * [`SoftwareKeyProtector`]  — AES-256-GCM under a KEK derived from a
//!     passphrase (the dev/test and no-hardware deployment backend), or
//!   * [`ExternalKeyProtector`]  — a TPM 2.0, a PKCS#11 token, or an HSM, reached
//!     through a [`TokenSealer`] adapter (e.g. [`CommandSealer`], which drives the
//!     vendor/`tpm2`/`pkcs11` tooling). The seed is sealed to hardware and never
//!     stored in plaintext on disk.
//!
//! A [`SealedKeystore`] bundles the sealed hybrid identity seeds (Ed25519 +
//! ML-DSA-65) into one self-contained, air-gap-transportable blob and reconstructs
//! the [`crate::identity::SoftwareSigner`] only after unsealing — so the keys at
//! rest are protected by the chosen backend, while the signing path stays the
//! existing audited code.
//!
//! ## What is validated where (honesty)
//!
//! The software backend and the abstraction are unit-tested here. The TPM and
//! PKCS#11 backends are validated against **software substitutes** (`swtpm`,
//! SoftHSM2) by `scripts/{tpm,pkcs11}_validate.sh` and the `#[ignore]`d
//! `tests/keystore_external_tests.rs` — these exercise the *real* TPM2-ESAPI /
//! PKCS#11 code paths, but a **physical-device acceptance test is still required**
//! and is documented in `docs/{TPM,HSM}_INTEGRATION.md`. No claim of hardware
//! validation is made without the hardware.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use hkdf::Hkdf;
use rand_core::{OsRng, RngCore};
use sha2::Sha256;
use zeroize::Zeroizing;

const KEK_INFO: &[u8] = b"syntriass-overlay keystore kek v1";
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;

/// Which protection backend sealed a blob (recorded for operator visibility; the
/// unseal path is driven by the protector the caller supplies, not this tag).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Backend {
    Software,
    Tpm2,
    Pkcs11,
    Hsm,
}

impl Backend {
    fn tag(self) -> u8 {
        match self {
            Backend::Software => 1,
            Backend::Tpm2 => 2,
            Backend::Pkcs11 => 3,
            Backend::Hsm => 4,
        }
    }
    fn from_tag(t: u8) -> Option<Self> {
        match t {
            1 => Some(Backend::Software),
            2 => Some(Backend::Tpm2),
            3 => Some(Backend::Pkcs11),
            4 => Some(Backend::Hsm),
            _ => None,
        }
    }
}

/// Key-storage failure. Never carries secret material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeystoreError {
    /// Sealing failed (encrypt / backend error).
    Seal,
    /// Unsealing failed: wrong key/passphrase, tampered blob, or backend error.
    Unseal,
    /// A stored blob was truncated, the wrong length, or had a bad tag.
    Malformed,
    /// The external backend was unavailable or returned an error.
    Backend(String),
}

/// The seal/unseal contract every backend implements.
pub trait KeyProtector {
    fn backend(&self) -> Backend;
    /// Seal `secret` for `label` (the label is bound into the blob so a blob for
    /// one purpose cannot be substituted for another).
    fn seal(&self, label: &str, secret: &[u8]) -> Result<Vec<u8>, KeystoreError>;
    /// Unseal a blob produced by [`seal`](Self::seal) for the same `label`.
    fn unseal(&self, label: &str, sealed: &[u8]) -> Result<Zeroizing<Vec<u8>>, KeystoreError>;
}

// ------------------------------- software backend -------------------------------

/// AES-256-GCM key protection under a KEK derived from a passphrase.
///
/// `KEK = HKDF-SHA256(salt, passphrase, "…kek v1")`; a fresh random salt + nonce
/// per seal. The `label` is the AEAD associated data, binding the blob to its
/// purpose. Blob = `salt(16) || nonce(12) || ciphertext+tag`.
///
/// Production note: a *passphrase* should be high-entropy or stretched with a
/// memory-hard KDF (argon2id) — HKDF is not a slow KDF. The stronger posture is
/// to make the KEK a **hardware-held** key via [`ExternalKeyProtector`]; this
/// software backend is the no-hardware / dev path. (Documented in
/// `docs/KEY_STORAGE_ARCHITECTURE.md`.)
pub struct SoftwareKeyProtector {
    passphrase: Zeroizing<Vec<u8>>,
}

impl SoftwareKeyProtector {
    pub fn new(passphrase: &[u8]) -> Self {
        Self {
            passphrase: Zeroizing::new(passphrase.to_vec()),
        }
    }

    fn derive_kek(&self, salt: &[u8]) -> Zeroizing<[u8; 32]> {
        let hk = Hkdf::<Sha256>::new(Some(salt), &self.passphrase);
        let mut kek = Zeroizing::new([0u8; 32]);
        hk.expand(KEK_INFO, kek.as_mut())
            .expect("32 bytes is within HKDF output bounds");
        kek
    }
}

impl KeyProtector for SoftwareKeyProtector {
    fn backend(&self) -> Backend {
        Backend::Software
    }

    fn seal(&self, label: &str, secret: &[u8]) -> Result<Vec<u8>, KeystoreError> {
        let mut salt = [0u8; SALT_LEN];
        let mut nonce = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut salt);
        OsRng.fill_bytes(&mut nonce);
        let kek = self.derive_kek(&salt);
        let cipher = Aes256Gcm::new_from_slice(kek.as_ref()).map_err(|_| KeystoreError::Seal)?;
        let ct = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: secret,
                    aad: label.as_bytes(),
                },
            )
            .map_err(|_| KeystoreError::Seal)?;
        let mut out = Vec::with_capacity(SALT_LEN + NONCE_LEN + ct.len());
        out.extend_from_slice(&salt);
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ct);
        Ok(out)
    }

    fn unseal(&self, label: &str, sealed: &[u8]) -> Result<Zeroizing<Vec<u8>>, KeystoreError> {
        if sealed.len() < SALT_LEN + NONCE_LEN + 16 {
            return Err(KeystoreError::Malformed);
        }
        let salt = &sealed[..SALT_LEN];
        let nonce = &sealed[SALT_LEN..SALT_LEN + NONCE_LEN];
        let ct = &sealed[SALT_LEN + NONCE_LEN..];
        let kek = self.derive_kek(salt);
        let cipher = Aes256Gcm::new_from_slice(kek.as_ref()).map_err(|_| KeystoreError::Unseal)?;
        let pt = cipher
            .decrypt(
                Nonce::from_slice(nonce),
                Payload {
                    msg: ct,
                    aad: label.as_bytes(),
                },
            )
            .map_err(|_| KeystoreError::Unseal)?;
        Ok(Zeroizing::new(pt))
    }
}

// ------------------------------- external backend -------------------------------

/// A hardware/token sealer: the bytes-in / bytes-out contract a TPM, PKCS#11
/// token, or HSM adapter implements. The secret never appears on disk in clear;
/// the returned `sealed` blob is whatever the backend produces (a TPM-wrapped
/// object, a PKCS#11-wrapped key, …) and is only openable with that backend.
pub trait TokenSealer: Send + Sync {
    fn seal_secret(&self, label: &str, secret: &[u8]) -> Result<Vec<u8>, KeystoreError>;
    fn unseal_secret(
        &self,
        label: &str,
        sealed: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, KeystoreError>;
}

/// Wraps any [`TokenSealer`] as a [`KeyProtector`] tagged with its backend kind.
pub struct ExternalKeyProtector<T: TokenSealer> {
    backend: Backend,
    sealer: T,
}

impl<T: TokenSealer> ExternalKeyProtector<T> {
    pub fn new(backend: Backend, sealer: T) -> Self {
        Self { backend, sealer }
    }
}

impl<T: TokenSealer> KeyProtector for ExternalKeyProtector<T> {
    fn backend(&self) -> Backend {
        self.backend
    }
    fn seal(&self, label: &str, secret: &[u8]) -> Result<Vec<u8>, KeystoreError> {
        self.sealer.seal_secret(label, secret)
    }
    fn unseal(&self, label: &str, sealed: &[u8]) -> Result<Zeroizing<Vec<u8>>, KeystoreError> {
        self.sealer.unseal_secret(label, sealed)
    }
}

/// A [`TokenSealer`] that drives an external command (the vendor/`tpm2`/`pkcs11`
/// tooling). The secret is written to the seal command's stdin and the sealed
/// blob read from its stdout; unseal is the reverse. The `label` is exported as
/// `SYNTRIASS_SEAL_LABEL`. This is the adapter that connects the abstraction to
/// `scripts/tpm_seal.sh` / `scripts/pkcs11_seal.sh` (validated against
/// `swtpm`/SoftHSM2; see `tests/keystore_external_tests.rs`).
pub struct CommandSealer {
    pub seal_argv: Vec<String>,
    pub unseal_argv: Vec<String>,
}

impl CommandSealer {
    fn run(argv: &[String], label: &str, input: &[u8]) -> Result<Vec<u8>, KeystoreError> {
        use std::io::Write;
        use std::process::{Command, Stdio};
        let (prog, args) = argv
            .split_first()
            .ok_or_else(|| KeystoreError::Backend("empty command".into()))?;
        let mut child = Command::new(prog)
            .args(args)
            .env("SYNTRIASS_SEAL_LABEL", label)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| KeystoreError::Backend(format!("spawn {prog}: {e}")))?;
        child
            .stdin
            .take()
            .ok_or_else(|| KeystoreError::Backend("no stdin".into()))?
            .write_all(input)
            .map_err(|e| KeystoreError::Backend(format!("write stdin: {e}")))?;
        let out = child
            .wait_with_output()
            .map_err(|e| KeystoreError::Backend(format!("wait: {e}")))?;
        if !out.status.success() {
            return Err(KeystoreError::Backend(format!(
                "{prog} exit {}: {}",
                out.status,
                String::from_utf8_lossy(&out.stderr).trim()
            )));
        }
        Ok(out.stdout)
    }
}

impl TokenSealer for CommandSealer {
    fn seal_secret(&self, label: &str, secret: &[u8]) -> Result<Vec<u8>, KeystoreError> {
        Self::run(&self.seal_argv, label, secret)
    }
    fn unseal_secret(
        &self,
        label: &str,
        sealed: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, KeystoreError> {
        Ok(Zeroizing::new(Self::run(&self.unseal_argv, label, sealed)?))
    }
}

// ------------------------------- sealed keystore -------------------------------

const ED_LABEL: &str = "syntriass/ed25519-seed";
const ML_LABEL: &str = "syntriass/mldsa65-seed";
const KEYSTORE_MAGIC: &[u8; 4] = b"SKS1";

/// The sealed hybrid identity seeds, self-contained and air-gap transportable.
/// Keys at rest are protected by whatever [`KeyProtector`] sealed them; the raw
/// seeds exist in memory only transiently during [`unlock_signer`].
pub struct SealedKeystore {
    pub backend: Backend,
    pub node_id: [u8; 16],
    sealed_ed: Vec<u8>,
    sealed_ml: Vec<u8>,
}

impl SealedKeystore {
    /// Seal a node's hybrid seeds under `protector`.
    pub fn seal(
        protector: &dyn KeyProtector,
        node_id: [u8; 16],
        ed_seed: &[u8; 32],
        ml_seed: &[u8; 32],
    ) -> Result<Self, KeystoreError> {
        Ok(Self {
            backend: protector.backend(),
            node_id,
            sealed_ed: protector.seal(ED_LABEL, ed_seed)?,
            sealed_ml: protector.seal(ML_LABEL, ml_seed)?,
        })
    }

    /// Unseal both seeds (transiently) and build the hybrid signer.
    pub fn unlock_signer(
        &self,
        protector: &dyn KeyProtector,
    ) -> Result<crate::identity::SoftwareSigner, KeystoreError> {
        let ed = protector.unseal(ED_LABEL, &self.sealed_ed)?;
        let ml = protector.unseal(ML_LABEL, &self.sealed_ml)?;
        if ed.len() != 32 || ml.len() != 32 {
            return Err(KeystoreError::Malformed);
        }
        let mut ed_arr = [0u8; 32];
        let mut ml_arr = [0u8; 32];
        ed_arr.copy_from_slice(&ed);
        ml_arr.copy_from_slice(&ml);
        let signer = crate::identity::SoftwareSigner::from_seeds(ed_arr, ml_arr)
            .map_err(|_| KeystoreError::Unseal)?;
        ed_arr.fill(0);
        ml_arr.fill(0);
        Ok(signer)
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(KEYSTORE_MAGIC);
        out.push(self.backend.tag());
        out.extend_from_slice(&self.node_id);
        out.extend_from_slice(&(self.sealed_ed.len() as u32).to_be_bytes());
        out.extend_from_slice(&self.sealed_ed);
        out.extend_from_slice(&(self.sealed_ml.len() as u32).to_be_bytes());
        out.extend_from_slice(&self.sealed_ml);
        out
    }

    pub fn from_bytes(b: &[u8]) -> Result<Self, KeystoreError> {
        let mut p = 0usize;
        let take = |p: &mut usize, n: usize| -> Result<&[u8], KeystoreError> {
            let end = p.checked_add(n).ok_or(KeystoreError::Malformed)?;
            if end > b.len() {
                return Err(KeystoreError::Malformed);
            }
            let s = &b[*p..end];
            *p = end;
            Ok(s)
        };
        if take(&mut p, 4)? != KEYSTORE_MAGIC {
            return Err(KeystoreError::Malformed);
        }
        let backend = Backend::from_tag(take(&mut p, 1)?[0]).ok_or(KeystoreError::Malformed)?;
        let node_id: [u8; 16] = take(&mut p, 16)?.try_into().unwrap();
        let ed_len = u32::from_be_bytes(take(&mut p, 4)?.try_into().unwrap()) as usize;
        let sealed_ed = take(&mut p, ed_len)?.to_vec();
        let ml_len = u32::from_be_bytes(take(&mut p, 4)?.try_into().unwrap()) as usize;
        let sealed_ml = take(&mut p, ml_len)?.to_vec();
        if p != b.len() {
            return Err(KeystoreError::Malformed);
        }
        Ok(Self {
            backend,
            node_id,
            sealed_ed,
            sealed_ml,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::HybridSigner;

    #[test]
    fn software_seal_unseal_round_trips() {
        let p = SoftwareKeyProtector::new(b"correct horse battery staple");
        let secret = [0x42u8; 32];
        let sealed = p.seal("k", &secret).unwrap();
        assert_ne!(&sealed[..], &secret[..], "sealed must not equal plaintext");
        assert_eq!(&p.unseal("k", &sealed).unwrap()[..], &secret[..]);
    }

    #[test]
    fn wrong_passphrase_fails_closed() {
        let good = SoftwareKeyProtector::new(b"pass-A");
        let bad = SoftwareKeyProtector::new(b"pass-B");
        let sealed = good.seal("k", &[1u8; 32]).unwrap();
        assert_eq!(bad.unseal("k", &sealed), Err(KeystoreError::Unseal));
    }

    #[test]
    fn wrong_label_fails_closed() {
        let p = SoftwareKeyProtector::new(b"pw");
        let sealed = p.seal("label-A", &[7u8; 32]).unwrap();
        // The label is AEAD AAD: a blob sealed for one purpose can't be opened
        // under another.
        assert_eq!(p.unseal("label-B", &sealed), Err(KeystoreError::Unseal));
    }

    #[test]
    fn tampered_blob_fails_closed() {
        let p = SoftwareKeyProtector::new(b"pw");
        let mut sealed = p.seal("k", &[9u8; 32]).unwrap();
        let last = sealed.len() - 1;
        sealed[last] ^= 0x01;
        assert_eq!(p.unseal("k", &sealed), Err(KeystoreError::Unseal));
    }

    #[test]
    fn malformed_blobs_never_panic() {
        let p = SoftwareKeyProtector::new(b"pw");
        for len in 0..40 {
            assert!(p.unseal("k", &vec![0u8; len]).is_err());
        }
    }

    #[test]
    fn sealed_keystore_round_trips_and_reconstructs_signer() {
        let p = SoftwareKeyProtector::new(b"node-passphrase");
        let (ed, ml) = ([0x11u8; 32], [0x22u8; 32]);
        let reference = crate::identity::SoftwareSigner::from_seeds(ed, ml).unwrap();

        let ks = SealedKeystore::seal(&p, [0x33; 16], &ed, &ml).unwrap();
        // Serialize -> bytes -> parse (air-gap transport).
        let bytes = ks.to_bytes();
        let ks2 = SealedKeystore::from_bytes(&bytes).unwrap();
        assert_eq!(ks2.backend, Backend::Software);
        assert_eq!(ks2.node_id, [0x33; 16]);

        // Unlock reconstructs the SAME signer (public keys match).
        let signer = ks2.unlock_signer(&p).unwrap();
        assert_eq!(signer.ed25519_public(), reference.ed25519_public());
        assert_eq!(signer.mldsa65_public(), reference.mldsa65_public());
    }

    #[test]
    fn sealed_keystore_wrong_passphrase_cannot_unlock() {
        let good = SoftwareKeyProtector::new(b"good");
        let ks = SealedKeystore::seal(&good, [0; 16], &[1u8; 32], &[2u8; 32]).unwrap();
        let bad = SoftwareKeyProtector::new(b"bad");
        assert!(ks.unlock_signer(&bad).is_err());
    }

    #[test]
    fn sealed_keystore_from_bytes_rejects_truncation() {
        let p = SoftwareKeyProtector::new(b"pw");
        let full = SealedKeystore::seal(&p, [0; 16], &[1u8; 32], &[2u8; 32])
            .unwrap()
            .to_bytes();
        for len in 0..full.len() {
            assert!(SealedKeystore::from_bytes(&full[..len]).is_err());
        }
        assert!(SealedKeystore::from_bytes(&full).is_ok());
    }

    /// The external adapter plumbing, exercised with a trivial reversible command
    /// (`base64`) so it runs anywhere. Real TPM/PKCS#11 backends use the same
    /// `CommandSealer` path and are validated against swtpm/SoftHSM2 in
    /// `tests/keystore_external_tests.rs` (ignored by default).
    #[test]
    fn command_sealer_plumbing_round_trips() {
        let sealer = CommandSealer {
            seal_argv: vec!["base64".into()],
            unseal_argv: vec!["base64".into(), "-d".into()],
        };
        let p = ExternalKeyProtector::new(Backend::Tpm2, sealer);
        assert_eq!(p.backend(), Backend::Tpm2);
        let secret = [0xAB; 32];
        let sealed = p.seal("k", &secret).unwrap();
        let opened = p.unseal("k", &sealed).unwrap();
        assert_eq!(&opened[..], &secret[..]);
    }

    #[test]
    fn external_protector_seals_keystore_through_command() {
        // A full SealedKeystore through the external command path (base64 stand-in
        // for a token), proving the abstraction is backend-uniform.
        let sealer = CommandSealer {
            seal_argv: vec!["base64".into()],
            unseal_argv: vec!["base64".into(), "-d".into()],
        };
        let p = ExternalKeyProtector::new(Backend::Pkcs11, sealer);
        let (ed, ml) = ([0x5u8; 32], [0x6u8; 32]);
        let ks = SealedKeystore::seal(&p, [1; 16], &ed, &ml).unwrap();
        assert_eq!(ks.backend, Backend::Pkcs11);
        let signer = ks.unlock_signer(&p).unwrap();
        let reference = crate::identity::SoftwareSigner::from_seeds(ed, ml).unwrap();
        assert_eq!(signer.ed25519_public(), reference.ed25519_public());
    }
}
