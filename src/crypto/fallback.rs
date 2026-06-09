//! Authenticated PSK fallback handshake with downgrade-attack resistance.
//!
//! When a node's *local* posture is `EncryptedFallback` (its PQC control path is
//! degraded and a pre-shared key is configured) it negotiates a quantum-safe
//! AES-256-GCM tunnel over the wire using this two-message handshake:
//!
//! ```text
//!   initiator --FallbackHello{client_nonce}-->            responder
//!   initiator <--FallbackFinished{server_nonce, seal(CONFIRM)}-- responder
//! ```
//!
//! Security properties:
//!   * **PSK authentication.** The responder proves PSK possession by sealing a
//!     fixed confirmation string under the derived keys; an MITM without the PSK
//!     cannot produce it. The initiator proves possession implicitly on its first
//!     data record (the responder's first `open` fails closed otherwise). The
//!     confirmation string is not secret, so sending it before the initiator is
//!     authenticated leaks nothing.
//!   * **Downgrade resistance.** The decision to run this handshake is taken
//!     *locally* (never from a wire signal), so an MITM cannot push a healthy
//!     `FullPqc` node into fallback. A tampered/forged `FallbackFinished` fails
//!     the AEAD open -> [`FallbackError::DowngradeDetected`], which the caller
//!     turns into a high-severity alert + fail-closed abort.
//!   * **No plaintext.** Every outcome is either an encrypted session or an
//!     error; there is no cleartext path.
//!
//! Tradeoff: no forward secrecy (PSK reuse). That is the documented price of
//! availability under jamming, and it never sends cleartext.

use rand_core::{OsRng, RngCore};
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::{
    derive_fallback_session, CryptoError, SessionKeys, FALLBACK_NONCE_LEN, FALLBACK_PSK_LEN,
};

/// Fixed confirmation string the responder seals to prove PSK possession.
const FALLBACK_CONFIRM: &[u8] = b"syntriass-overlay psk-fallback confirm v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FallbackError {
    /// A frame had the wrong length / structure.
    Malformed,
    /// Key derivation failed (should not happen for valid inputs).
    Crypto,
    /// The confirmation did not authenticate: wrong PSK or active tampering.
    /// Callers MUST treat this as a downgrade attack (alert + fail closed).
    DowngradeDetected,
}

impl From<CryptoError> for FallbackError {
    fn from(_: CryptoError) -> Self {
        FallbackError::Crypto
    }
}

fn fresh_nonce() -> [u8; FALLBACK_NONCE_LEN] {
    let mut n = [0u8; FALLBACK_NONCE_LEN];
    OsRng.fill_bytes(&mut n);
    n
}

/// Retained initiator state between sending `FallbackHello` and receiving
/// `FallbackFinished`. Zeroizes the PSK on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct FallbackInitiator {
    psk: [u8; FALLBACK_PSK_LEN],
    client_nonce: [u8; FALLBACK_NONCE_LEN],
}

impl FallbackInitiator {
    /// Begin the fallback handshake: returns retained state and the
    /// `FallbackHello` payload (the client nonce).
    pub fn begin(psk: [u8; FALLBACK_PSK_LEN]) -> (Self, Vec<u8>) {
        let client_nonce = fresh_nonce();
        let hello = client_nonce.to_vec();
        (Self { psk, client_nonce }, hello)
    }

    /// Consume `FallbackFinished`, authenticate the responder, and return the
    /// established session. An authentication failure is a downgrade signal.
    pub fn finish(self, finished: &[u8]) -> Result<SessionKeys, FallbackError> {
        if finished.len() <= FALLBACK_NONCE_LEN {
            return Err(FallbackError::Malformed);
        }
        let mut server_nonce = [0u8; FALLBACK_NONCE_LEN];
        server_nonce.copy_from_slice(&finished[..FALLBACK_NONCE_LEN]);
        let confirm_ct = &finished[FALLBACK_NONCE_LEN..];

        let mut keys = derive_fallback_session(&self.psk, &self.client_nonce, &server_nonce, true)?;
        let opened = keys
            .open(confirm_ct)
            .map_err(|_| FallbackError::DowngradeDetected)?;
        if opened != FALLBACK_CONFIRM {
            return Err(FallbackError::DowngradeDetected);
        }
        Ok(keys)
    }
}

/// Responder side: consume `FallbackHello`, return the established session and
/// the `FallbackFinished` payload (server nonce + sealed confirmation).
pub fn respond(
    psk: &[u8; FALLBACK_PSK_LEN],
    hello: &[u8],
) -> Result<(SessionKeys, Vec<u8>), FallbackError> {
    if hello.len() != FALLBACK_NONCE_LEN {
        return Err(FallbackError::Malformed);
    }
    let mut client_nonce = [0u8; FALLBACK_NONCE_LEN];
    client_nonce.copy_from_slice(hello);
    let server_nonce = fresh_nonce();

    let mut keys = derive_fallback_session(psk, &client_nonce, &server_nonce, false)?;
    let confirm_ct = keys.seal(FALLBACK_CONFIRM).map_err(FallbackError::from)?;

    let mut finished = Vec::with_capacity(FALLBACK_NONCE_LEN + confirm_ct.len());
    finished.extend_from_slice(&server_nonce);
    finished.extend_from_slice(&confirm_ct);
    Ok((keys, finished))
}

#[cfg(test)]
mod tests {
    use super::*;

    const PSK: [u8; FALLBACK_PSK_LEN] = [0x5c; FALLBACK_PSK_LEN];

    #[test]
    fn happy_path_establishes_encrypted_session() {
        let (init, hello) = FallbackInitiator::begin(PSK);
        let (mut server, finished) = respond(&PSK, &hello).unwrap();
        let mut client = init.finish(&finished).unwrap();

        // The confirmation consumed the responder's first s2c record (nonce 0);
        // application traffic continues from there, in sync, both ways.
        let c2s = b"degraded-but-encrypted";
        let ct = client.seal(c2s).unwrap();
        assert_ne!(&ct[..], &c2s[..], "must be ciphertext, never plaintext");
        assert_eq!(server.open(&ct).unwrap(), c2s);

        let s2c = b"ack";
        let ct = server.seal(s2c).unwrap();
        assert_eq!(client.open(&ct).unwrap(), s2c);
    }

    #[test]
    fn wrong_psk_is_downgrade_detected() {
        let (init, hello) = FallbackInitiator::begin(PSK);
        let (_server, finished) = respond(&[0x11; FALLBACK_PSK_LEN], &hello).unwrap();
        assert_eq!(
            init.finish(&finished).unwrap_err(),
            FallbackError::DowngradeDetected
        );
    }

    #[test]
    fn tampered_finished_is_downgrade_detected() {
        let (init, hello) = FallbackInitiator::begin(PSK);
        let (_server, mut finished) = respond(&PSK, &hello).unwrap();
        let last = finished.len() - 1;
        finished[last] ^= 0x01;
        assert_eq!(
            init.finish(&finished).unwrap_err(),
            FallbackError::DowngradeDetected
        );
    }

    #[test]
    fn malformed_frames_rejected() {
        assert_eq!(
            respond(&PSK, &[0u8; 4]).unwrap_err(),
            FallbackError::Malformed
        );
        let (init, _hello) = FallbackInitiator::begin(PSK);
        assert_eq!(
            init.finish(&[0u8; FALLBACK_NONCE_LEN]).unwrap_err(),
            FallbackError::Malformed
        );
    }

    #[test]
    fn distinct_nonces_per_session() {
        let (_i1, h1) = FallbackInitiator::begin(PSK);
        let (_i2, h2) = FallbackInitiator::begin(PSK);
        assert_ne!(h1, h2, "client nonce must be fresh per session");
    }
}
