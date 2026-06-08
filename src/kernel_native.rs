//! User-space control-plane types for the kernel-native Syntriass architecture.
//!
//! The eBPF program is responsible for detecting sockets that need enforcement.
//! This module owns the stable daemon-side contract: parse the up-call, run the
//! configured hybrid PQC handshake, and fail closed unless kTLS configuration
//! succeeds.
//!
//! What is real here (and exercised by `tests/ktls_roundtrip.rs`):
//!   * [`attach_tls_ulp`], [`install_ktls_tx`], [`install_ktls_rx`] and
//!     [`install_ktls_duplex`] perform the actual Linux kernel-TLS handoff via
//!     `setsockopt(SOL_TCP, TCP_ULP, "tls")` then
//!     `setsockopt(SOL_TLS, TLS_TX|TLS_RX, ...)` with a TLS 1.3 AES-256-GCM
//!     `tls12_crypto_info_aes_gcm_256` payload. Once installed, the kernel
//!     encrypts/decrypts the stream natively.
//!   * [`ktls_supported`] probes whether the running kernel exposes the TLS ULP.
//!
//! What is still a stub (honestly): [`complete_kernel_upcall`] cannot yet derive
//! TLS-1.3 record secrets from the hybrid PQC handshake. `SessionKeys`
//! deliberately never exposes raw key bytes, and kTLS speaks TLS records rather
//! than the v1 custom frame, so that export bridge is separate work. Until it
//! exists the enforce path fails closed via [`KernelNativeError::KeyExportUnsupported`].

use crate::crypto::{self, CipherSuite, CryptoError};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::os::unix::io::RawFd;
use zeroize::{Zeroize, ZeroizeOnDrop};

pub const DEFAULT_UPCALL_SOCKET: &str = "/var/run/syntriass.sock";

/// TLS 1.3 AES-256-GCM key-material sizes (Linux uapi `linux/tls.h`).
pub const KTLS_KEY_LEN: usize = 32;
pub const KTLS_SALT_LEN: usize = 4;
pub const KTLS_IV_LEN: usize = 8;
pub const KTLS_REC_SEQ_LEN: usize = 8;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct KernelUpcall {
    pub socket_id: u64,
    pub local_port: u16,
    pub remote_port: u16,
    pub remote_addr: String,
    #[serde(default)]
    pub cgroup_id: Option<u64>,
    #[serde(default)]
    pub pid: Option<u32>,
    #[serde(default)]
    pub fd: Option<RawFd>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnforcementDecision {
    Enforce,
    Ignore,
}

#[derive(Debug)]
pub enum KernelNativeError {
    Config,
    Crypto(CryptoError),
    MissingSocketReference,
    /// The running kernel does not expose the TLS ULP (no `tls` module).
    KtlsUnavailable,
    /// A kTLS `setsockopt` call failed for a reason other than missing support.
    Ktls(KtlsError),
    /// Deriving TLS-1.3 record secrets from the PQC handshake is not yet built.
    KeyExportUnsupported,
}

impl fmt::Display for KernelNativeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KernelNativeError::Config => {
                write!(f, "kernel-native policy or identity is unavailable")
            }
            KernelNativeError::Crypto(e) => write!(f, "hybrid PQC handshake failed: {e:?}"),
            KernelNativeError::MissingSocketReference => {
                write!(
                    f,
                    "kernel upcall did not include an installable socket reference"
                )
            }
            KernelNativeError::KtlsUnavailable => {
                write!(f, "kernel TLS (kTLS) ULP is unavailable on this host")
            }
            KernelNativeError::Ktls(e) => write!(f, "{e}"),
            KernelNativeError::KeyExportUnsupported => write!(
                f,
                "PQC-to-kTLS record secret export is not yet implemented (fail closed)"
            ),
        }
    }
}

impl std::error::Error for KernelNativeError {}

impl From<KtlsError> for KernelNativeError {
    fn from(e: KtlsError) -> Self {
        if e.is_unsupported() {
            KernelNativeError::KtlsUnavailable
        } else {
            KernelNativeError::Ktls(e)
        }
    }
}

pub fn classify_upcall(upcall: &KernelUpcall) -> EnforcementDecision {
    if upcall.local_port == 0 || upcall.remote_port == 0 {
        EnforcementDecision::Ignore
    } else {
        EnforcementDecision::Enforce
    }
}

pub fn configured_suite() -> Result<CipherSuite, KernelNativeError> {
    crypto::resolve_policy().map_err(|_| KernelNativeError::Config)
}

pub fn execute_local_handshake_probe(suite: CipherSuite) -> Result<(), KernelNativeError> {
    let identity = crypto::resolve_identity().map_err(KernelNativeError::Crypto)?;
    let engine = suite.engine();
    let (_initiator_state, client_hello) = engine
        .begin_initiator(&identity)
        .map_err(KernelNativeError::Crypto)?;
    let (_keys, _server_hello) = engine
        .respond(&identity, &client_hello)
        .map_err(KernelNativeError::Crypto)?;
    Ok(())
}

pub fn complete_kernel_upcall(upcall: &KernelUpcall) -> Result<(), KernelNativeError> {
    if classify_upcall(upcall) == EnforcementDecision::Ignore {
        return Ok(());
    }
    let suite = configured_suite()?;
    execute_local_handshake_probe(suite)?;
    let _fd = upcall.fd.ok_or(KernelNativeError::MissingSocketReference)?;
    // The kTLS install primitives below this point are real and tested, but the
    // step that turns this socket's hybrid PQC handshake into TLS-1.3 record
    // secrets does not exist yet (see module docs). Fail closed rather than
    // pretend a tunnel was established.
    Err(KernelNativeError::KeyExportUnsupported)
}

// ----------------------------- Kernel TLS (kTLS) -----------------------------

/// TLS 1.3 AES-256-GCM key material for a single direction (TX or RX).
///
/// `tx` on one peer must equal `rx` on the other for that direction, and both
/// peers must use the same TLS version, otherwise the kernel computes different
/// AEAD nonces and authentication fails. Raw bytes are zeroized on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct KtlsSecrets {
    pub key: [u8; KTLS_KEY_LEN],
    pub salt: [u8; KTLS_SALT_LEN],
    pub iv: [u8; KTLS_IV_LEN],
    pub rec_seq: [u8; KTLS_REC_SEQ_LEN],
}

impl fmt::Debug for KtlsSecrets {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never print key material.
        f.debug_struct("KtlsSecrets").finish_non_exhaustive()
    }
}

/// Both directions for one connected socket.
#[derive(Clone, Debug)]
pub struct KtlsDuplexKeys {
    pub tx: KtlsSecrets,
    pub rx: KtlsSecrets,
}

/// A kTLS `setsockopt` failure, tagged with the stage that produced it.
#[derive(Debug, Clone, Copy)]
pub struct KtlsError {
    pub stage: &'static str,
    pub errno: i32,
}

impl KtlsError {
    /// True when the failure means "this kernel has no TLS ULP" rather than a
    /// genuine misconfiguration. Callers use this to skip (tests) or fail
    /// closed with a precise reason (daemon).
    pub fn is_unsupported(&self) -> bool {
        matches!(
            self.errno,
            libc::ENOENT | libc::EOPNOTSUPP | libc::ENOPROTOOPT | libc::EPROTONOSUPPORT
        )
    }
}

impl fmt::Display for KtlsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let msg = std::io::Error::from_raw_os_error(self.errno);
        write!(
            f,
            "kTLS {} failed: errno {} ({msg})",
            self.stage, self.errno
        )
    }
}

impl std::error::Error for KtlsError {}

#[cfg(target_os = "linux")]
mod sys {
    use libc::c_int;

    // From linux/tls.h and linux/tcp.h; libc does not expose these.
    pub const TCP_ULP: c_int = 31;
    pub const SOL_TLS: c_int = 282;
    pub const TLS_TX: c_int = 1;
    pub const TLS_RX: c_int = 2;
    pub const TLS_1_3_VERSION: u16 = 0x0304;
    pub const TLS_CIPHER_AES_GCM_256: u16 = 52;

    /// Mirrors `struct tls_crypto_info`.
    #[repr(C)]
    pub struct TlsCryptoInfo {
        pub version: u16,
        pub cipher_type: u16,
    }

    /// Mirrors `struct tls12_crypto_info_aes_gcm_256` (56 bytes, field order is
    /// load-bearing: the kernel reads it positionally).
    #[repr(C)]
    pub struct Tls12CryptoInfoAesGcm256 {
        pub info: TlsCryptoInfo,
        pub iv: [u8; super::KTLS_IV_LEN],
        pub key: [u8; super::KTLS_KEY_LEN],
        pub salt: [u8; super::KTLS_SALT_LEN],
        pub rec_seq: [u8; super::KTLS_REC_SEQ_LEN],
    }
}

/// Returns true if the running kernel exposes the TLS ULP.
///
/// Probes by attempting `setsockopt(TCP_ULP, "tls")` on a throwaway TCP socket.
/// A missing `tls` module yields `ENOENT`; a present ULP yields success or a
/// state error (e.g. `ENOTCONN`) — both of which mean "supported".
#[cfg(target_os = "linux")]
pub fn ktls_supported() -> bool {
    unsafe {
        let fd = libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0);
        if fd < 0 {
            return false;
        }
        let ulp = b"tls";
        let rc = libc::setsockopt(
            fd,
            libc::IPPROTO_TCP,
            sys::TCP_ULP,
            ulp.as_ptr() as *const libc::c_void,
            ulp.len() as libc::socklen_t,
        );
        let errno = if rc != 0 {
            std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
        } else {
            0
        };
        libc::close(fd);
        if rc == 0 {
            return true;
        }
        !matches!(
            errno,
            libc::ENOENT | libc::EOPNOTSUPP | libc::ENOPROTOOPT | libc::EPROTONOSUPPORT
        )
    }
}

#[cfg(not(target_os = "linux"))]
pub fn ktls_supported() -> bool {
    false
}

/// Attach the kernel TLS ULP to a connected TCP socket. Call once, after the
/// TCP handshake (connect/accept) and before installing TX/RX keys.
#[cfg(target_os = "linux")]
pub fn attach_tls_ulp(fd: RawFd) -> Result<(), KtlsError> {
    let ulp = b"tls";
    let rc = unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_TCP,
            sys::TCP_ULP,
            ulp.as_ptr() as *const libc::c_void,
            ulp.len() as libc::socklen_t,
        )
    };
    if rc != 0 {
        return Err(last_ktls_error("TCP_ULP=tls"));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn install_direction(
    fd: RawFd,
    direction: libc::c_int,
    stage: &'static str,
    secrets: &KtlsSecrets,
) -> Result<(), KtlsError> {
    let mut info = sys::Tls12CryptoInfoAesGcm256 {
        info: sys::TlsCryptoInfo {
            version: sys::TLS_1_3_VERSION,
            cipher_type: sys::TLS_CIPHER_AES_GCM_256,
        },
        iv: secrets.iv,
        key: secrets.key,
        salt: secrets.salt,
        rec_seq: secrets.rec_seq,
    };
    let rc = unsafe {
        libc::setsockopt(
            fd,
            sys::SOL_TLS,
            direction,
            (&info as *const sys::Tls12CryptoInfoAesGcm256) as *const libc::c_void,
            std::mem::size_of::<sys::Tls12CryptoInfoAesGcm256>() as libc::socklen_t,
        )
    };
    // Scrub the transient copy of the key material regardless of outcome.
    info.key.zeroize();
    info.iv.zeroize();
    info.salt.zeroize();
    info.rec_seq.zeroize();
    if rc != 0 {
        return Err(last_ktls_error(stage));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn last_ktls_error(stage: &'static str) -> KtlsError {
    KtlsError {
        stage,
        errno: std::io::Error::last_os_error().raw_os_error().unwrap_or(0),
    }
}

/// Install the transmit (encrypt) key for a kTLS socket. Requires a prior
/// [`attach_tls_ulp`].
#[cfg(target_os = "linux")]
pub fn install_ktls_tx(fd: RawFd, secrets: &KtlsSecrets) -> Result<(), KtlsError> {
    install_direction(fd, sys::TLS_TX, "TLS_TX", secrets)
}

/// Install the receive (decrypt) key for a kTLS socket. Requires a prior
/// [`attach_tls_ulp`].
#[cfg(target_os = "linux")]
pub fn install_ktls_rx(fd: RawFd, secrets: &KtlsSecrets) -> Result<(), KtlsError> {
    install_direction(fd, sys::TLS_RX, "TLS_RX", secrets)
}

/// Attach the TLS ULP and install both directions on a connected socket.
#[cfg(target_os = "linux")]
pub fn install_ktls_duplex(fd: RawFd, keys: &KtlsDuplexKeys) -> Result<(), KtlsError> {
    attach_tls_ulp(fd)?;
    install_ktls_tx(fd, &keys.tx)?;
    install_ktls_rx(fd, &keys.rx)?;
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub fn attach_tls_ulp(_fd: RawFd) -> Result<(), KtlsError> {
    Err(KtlsError {
        stage: "TCP_ULP=tls",
        errno: libc::ENOSYS,
    })
}

#[cfg(not(target_os = "linux"))]
pub fn install_ktls_tx(_fd: RawFd, _secrets: &KtlsSecrets) -> Result<(), KtlsError> {
    Err(KtlsError {
        stage: "TLS_TX",
        errno: libc::ENOSYS,
    })
}

#[cfg(not(target_os = "linux"))]
pub fn install_ktls_rx(_fd: RawFd, _secrets: &KtlsSecrets) -> Result<(), KtlsError> {
    Err(KtlsError {
        stage: "TLS_RX",
        errno: libc::ENOSYS,
    })
}

#[cfg(not(target_os = "linux"))]
pub fn install_ktls_duplex(_fd: RawFd, _keys: &KtlsDuplexKeys) -> Result<(), KtlsError> {
    Err(KtlsError {
        stage: "TCP_ULP=tls",
        errno: libc::ENOSYS,
    })
}

/// Install duplex kTLS keys on `fd`, mapping low-level failures into the
/// kernel-native error taxonomy (missing-ULP becomes `KtlsUnavailable`).
pub fn install_ktls_keys(fd: RawFd, keys: &KtlsDuplexKeys) -> Result<(), KernelNativeError> {
    install_ktls_duplex(fd, keys).map_err(KernelNativeError::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
    #[test]
    fn crypto_info_struct_is_56_bytes() {
        // Field order and packing must match the kernel uapi exactly.
        assert_eq!(std::mem::size_of::<sys::Tls12CryptoInfoAesGcm256>(), 56);
    }

    #[test]
    fn unsupported_classification() {
        let e = KtlsError {
            stage: "TCP_ULP=tls",
            errno: libc::ENOENT,
        };
        assert!(e.is_unsupported());
        assert!(matches!(
            KernelNativeError::from(e),
            KernelNativeError::KtlsUnavailable
        ));
        let real = KtlsError {
            stage: "TLS_TX",
            errno: libc::EINVAL,
        };
        assert!(!real.is_unsupported());
        assert!(matches!(
            KernelNativeError::from(real),
            KernelNativeError::Ktls(_)
        ));
    }

    #[test]
    fn secrets_debug_hides_key_material() {
        let s = KtlsSecrets {
            key: [0xAB; KTLS_KEY_LEN],
            salt: [0xCD; KTLS_SALT_LEN],
            iv: [0xEF; KTLS_IV_LEN],
            rec_seq: [0; KTLS_REC_SEQ_LEN],
        };
        let rendered = format!("{s:?}");
        assert!(!rendered.contains("ab") && !rendered.contains("AB"));
    }
}
