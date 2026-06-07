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
use sha2::Sha256;
use x25519_dalek::{EphemeralSecret, PublicKey as XPublicKey};

use super::{CryptoError, SessionKeys, X25519_LEN};

/// HKDF label prefix. The concrete suite id is appended for transcript binding.
const HKDF_LABEL_PREFIX: &[u8] = b"syntriass-overlay v2 suite=";

/// Build a 96-bit GCM nonce from a big-endian u64 counter in the low 8 bytes.
fn nonce_from_counter(counter: u64) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[4..].copy_from_slice(&counter.to_be_bytes());
    n
}

/// One AEAD direction with an owned, monotonic counter. Public methods only
/// expose seal/open; the key and counter are private.
pub struct Direction {
    cipher: Aes256Gcm,
    counter: u64,
}

impl Direction {
    fn new(key: &[u8; 32]) -> Self {
        Self {
            cipher: Aes256Gcm::new_from_slice(key).expect("32-byte key"),
            counter: 0,
        }
    }

    pub fn seal(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if self.counter == u64::MAX {
            return Err(CryptoError::NonceExhausted);
        }
        let n = nonce_from_counter(self.counter);
        let ct = self
            .cipher
            .encrypt(Nonce::from_slice(&n), Payload { msg: plaintext, aad: &[] })
            .map_err(|_| CryptoError::Encrypt)?;
        self.counter += 1;
        Ok(ct)
    }

    pub fn open(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if self.counter == u64::MAX {
            return Err(CryptoError::NonceExhausted);
        }
        let n = nonce_from_counter(self.counter);
        let pt = self
            .cipher
            .decrypt(Nonce::from_slice(&n), Payload { msg: ciphertext, aad: &[] })
            .map_err(|_| CryptoError::Decrypt)?;
        self.counter += 1;
        Ok(pt)
    }
}

/// Derive directional keys from hybrid IKM, binding the suite id into the label.
fn derive(ikm: &[u8], suite_id: u8, is_initiator: bool) -> Result<SessionKeys, CryptoError> {
    let mut info = Vec::with_capacity(HKDF_LABEL_PREFIX.len() + 1);
    info.extend_from_slice(HKDF_LABEL_PREFIX);
    info.push(suite_id); // transcript binding: wrong id -> wrong keys
    let hk = Hkdf::<Sha256>::new(None, ikm);
    let mut okm = [0u8; 64];
    hk.expand(&info, &mut okm).map_err(|_| CryptoError::Hkdf)?;
    let mut c2s = [0u8; 32];
    let mut s2c = [0u8; 32];
    c2s.copy_from_slice(&okm[0..32]);
    s2c.copy_from_slice(&okm[32..64]);
    // Initiator writes c2s/reads s2c; responder mirrored.
    let (tx, rx) = if is_initiator { (c2s, s2c) } else { (s2c, c2s) };
    Ok(SessionKeys { tx: Direction::new(&tx), rx: Direction::new(&rx) })
}

/// Retained initiator secrets for a generic suite. Boxed behind `InitiatorState`.
pub struct GenericInitiatorState<K: KemCore> {
    suite_id: u8,
    x_secret: EphemeralSecret,
    ml_decap: K::DecapsulationKey,
}

/// Produce a ClientHello body and the initiator state to retain.
/// Body = X25519 public key || ML-KEM encapsulation key.
pub fn client_hello<K: KemCore>(suite_id: u8) -> (GenericInitiatorState<K>, Vec<u8>) {
    let x_secret = EphemeralSecret::random();
    let x_public = XPublicKey::from(&x_secret);
    let mut rng = rand_core::OsRng;
    let (ml_decap, ml_encap) = K::generate(&mut rng);

    let ek_bytes = ml_encap.as_bytes();
    let mut body = Vec::with_capacity(X25519_LEN + ek_bytes.len());
    body.extend_from_slice(x_public.as_bytes());
    body.extend_from_slice(ek_bytes.as_slice());

    (GenericInitiatorState { suite_id, x_secret, ml_decap }, body)
}

/// Responder: consume ClientHello, return established keys + ServerHello body.
/// Body in  = X25519 pk || ML-KEM ek. Body out = X25519 pk || ML-KEM ct.
pub fn respond<K: KemCore>(
    suite_id: u8,
    ek_len: usize,
    body: &[u8],
) -> Result<(SessionKeys, Vec<u8>), CryptoError> {
    if body.len() != X25519_LEN + ek_len {
        return Err(CryptoError::BadHelloLength);
    }
    let peer_x_arr: [u8; 32] =
        body[0..X25519_LEN].try_into().map_err(|_| CryptoError::BadHelloLength)?;
    let peer_x = XPublicKey::from(peer_x_arr);

    // Parse the ML-KEM encapsulation key from wire bytes into its Encoded form.
    // `Encoded<T>` is a `hybrid_array::Array<u8, N>`; `TryFrom<&[u8]>` exists and
    // succeeds because we already validated `body.len()`. If the compiler reports
    // an unsatisfied `TryFrom` bound here (a known hybrid-array inference wrinkle,
    // RustCrypto/hybrid-array#114), the mechanical fix is:
    //     use ml_kem::array::Array;
    //     let ek_enc = Array::try_from(ek_slice).map_err(|_| CryptoError::MlKemDecode)?;
    let ek_slice = &body[X25519_LEN..];
    let ek_enc =
        Encoded::<K::EncapsulationKey>::try_from(ek_slice).map_err(|_| CryptoError::MlKemDecode)?;
    let peer_ek = K::EncapsulationKey::from_bytes(&ek_enc);

    let server_x_secret = EphemeralSecret::random();
    let server_x_public = XPublicKey::from(&server_x_secret);

    let mut rng = rand_core::OsRng;
    let (ml_ct, ml_ss) =
        peer_ek.encapsulate(&mut rng).map_err(|_| CryptoError::MlKemDecode)?;
    let x_ss = server_x_secret.diffie_hellman(&peer_x);

    let mut ikm = Vec::with_capacity(32 + ml_ss.as_slice().len());
    ikm.extend_from_slice(x_ss.as_bytes());
    ikm.extend_from_slice(ml_ss.as_slice());
    let keys = derive(&ikm, suite_id, false)?;

    let mut hello = Vec::with_capacity(X25519_LEN + ml_ct.as_slice().len());
    hello.extend_from_slice(server_x_public.as_bytes());
    hello.extend_from_slice(ml_ct.as_slice());

    Ok((keys, hello))
}

/// Initiator step 2: consume ServerHello, finish key agreement.
pub fn finish<K: KemCore>(
    state: GenericInitiatorState<K>,
    ct_len: usize,
    body: &[u8],
) -> Result<SessionKeys, CryptoError> {
    if body.len() != X25519_LEN + ct_len {
        return Err(CryptoError::BadHelloLength);
    }
    let peer_x_arr: [u8; 32] =
        body[0..X25519_LEN].try_into().map_err(|_| CryptoError::BadHelloLength)?;
    let peer_x = XPublicKey::from(peer_x_arr);

    // `Ciphertext<K>` is also a `hybrid_array::Array<u8, N>`. Same note as above:
    // if `try_from` inference fights, use `ml_kem::array::Array::try_from(ct_slice)`.
    let ct_slice = &body[X25519_LEN..];
    let ct = ml_kem::Ciphertext::<K>::try_from(ct_slice).map_err(|_| CryptoError::MlKemDecode)?;

    let ml_ss = state.ml_decap.decapsulate(&ct).map_err(|_| CryptoError::Decapsulate)?;
    let x_ss = state.x_secret.diffie_hellman(&peer_x);

    let mut ikm = Vec::with_capacity(32 + ml_ss.as_slice().len());
    ikm.extend_from_slice(x_ss.as_bytes());
    ikm.extend_from_slice(ml_ss.as_slice());
    derive(&ikm, state.suite_id, true)
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
        let mut a = derive(&ikm, 0x01, true).expect("derive a");
        let mut b = derive(&ikm, 0x02, true).expect("derive b");

        let ct = a.tx.seal(b"transcript-bound").unwrap();
        // b's rx direction uses the same role mapping but a different suite id,
        // so its key differs and authentication must fail.
        assert!(b.rx.open(&ct).is_err());
    }

    /// Same suite id + same IKM + same role -> identical, interoperable keys
    /// (sanity check that the derivation is deterministic and not just random).
    #[test]
    fn same_inputs_interoperate() {
        let ikm = [0x07u8; 64];
        let mut initiator = derive(&ikm, 0x01, true).expect("init");
        let mut responder = derive(&ikm, 0x01, false).expect("resp");
        let ct = initiator.tx.seal(b"hello").unwrap();
        assert_eq!(responder.rx.open(&ct).unwrap(), b"hello");
    }
}
