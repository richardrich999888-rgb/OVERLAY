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
//! The PQC -> kTLS bridge is now wired: [`bridge_session_to_ktls`] exports the
//! established hybrid session's traffic keys (via `SessionKeys::export_ktls`),
//! packs them into `tls12_crypto_info_aes_gcm_256`, and installs them with
//! `setsockopt`. On any kTLS failure it tears the socket down (shutdown + close)
//! so cleartext can never escape. [`KernelSockEvent`] is the binary contract the
//! eBPF RingBuf emits and the daemon decodes.

use crate::crypto::{self, CipherSuite, CryptoError, KtlsTrafficSecret, SessionKeys};
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

/// Binary connection event emitted by the eBPF sockops program into the pinned
/// RingBuf and decoded by the daemon. `#[repr(C)]` with a fixed layout so the
/// kernel and user space agree byte-for-byte; addresses are stored as 16 bytes
/// (IPv4 lives in the first 4) and `family` is `AF_INET`/`AF_INET6`.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KernelSockEvent {
    pub cookie: u64,
    pub cgroup_id: u64,
    pub src_addr: [u8; 16],
    pub dst_addr: [u8; 16],
    pub src_port: u16,
    pub dst_port: u16,
    pub family: u16,
    pub _pad: u16,
}

// Compile-time ABI guard. `KernelSockEvent` (user space) and `maps::SockEvent`
// (kernel, in the out-of-tree ebpf crate) MUST be byte-identical. Any reorder,
// resize, or alignment change here fails `cargo check` immediately instead of
// becoming a silent kernel<->user wire mismatch. The kernel side carries the
// mirror of these asserts in `ebpf/src/maps.rs`.
const _: () = {
    use core::mem::{align_of, offset_of, size_of};
    assert!(
        size_of::<KernelSockEvent>() == 56,
        "KernelSockEvent must be 56 bytes"
    );
    assert!(
        align_of::<KernelSockEvent>() == 8,
        "KernelSockEvent must be 8-byte aligned"
    );
    assert!(offset_of!(KernelSockEvent, cookie) == 0);
    assert!(offset_of!(KernelSockEvent, cgroup_id) == 8);
    assert!(offset_of!(KernelSockEvent, src_addr) == 16);
    assert!(offset_of!(KernelSockEvent, dst_addr) == 32);
    assert!(offset_of!(KernelSockEvent, src_port) == 48);
    assert!(offset_of!(KernelSockEvent, dst_port) == 50);
    assert!(offset_of!(KernelSockEvent, family) == 52);
    assert!(offset_of!(KernelSockEvent, _pad) == 54);
};

impl KernelSockEvent {
    pub const WIRE_LEN: usize = core::mem::size_of::<KernelSockEvent>();

    /// Decode one RingBuf record. Returns `None` if the slice is too short.
    pub fn from_bytes(buf: &[u8]) -> Option<Self> {
        if buf.len() < Self::WIRE_LEN {
            return None;
        }
        let rd16 = |o: usize| {
            let mut a = [0u8; 16];
            a.copy_from_slice(&buf[o..o + 16]);
            a
        };
        let rd_u64 = |o: usize| u64::from_ne_bytes(buf[o..o + 8].try_into().unwrap());
        let rd_u16 = |o: usize| u16::from_ne_bytes(buf[o..o + 2].try_into().unwrap());
        Some(KernelSockEvent {
            cookie: rd_u64(0),
            cgroup_id: rd_u64(8),
            src_addr: rd16(16),
            dst_addr: rd16(32),
            src_port: rd_u16(48),
            dst_port: rd_u16(50),
            family: rd_u16(52),
            _pad: rd_u16(54),
        })
    }

    /// Serialize to the on-wire layout (used by tests and by a user-space
    /// re-emitter; the kernel writes this layout natively).
    pub fn to_bytes(&self) -> [u8; Self::WIRE_LEN] {
        let mut out = [0u8; Self::WIRE_LEN];
        out[0..8].copy_from_slice(&self.cookie.to_ne_bytes());
        out[8..16].copy_from_slice(&self.cgroup_id.to_ne_bytes());
        out[16..32].copy_from_slice(&self.src_addr);
        out[32..48].copy_from_slice(&self.dst_addr);
        out[48..50].copy_from_slice(&self.src_port.to_ne_bytes());
        out[50..52].copy_from_slice(&self.dst_port.to_ne_bytes());
        out[52..54].copy_from_slice(&self.family.to_ne_bytes());
        out[54..56].copy_from_slice(&self._pad.to_ne_bytes());
        out
    }

    /// Render the destination address as a string for [`KernelUpcall`].
    pub fn dst_addr_string(&self) -> String {
        if self.family == libc::AF_INET6 as u16 {
            let mut seg = [0u16; 8];
            for (i, s) in seg.iter_mut().enumerate() {
                *s = u16::from_be_bytes([self.dst_addr[i * 2], self.dst_addr[i * 2 + 1]]);
            }
            std::net::Ipv6Addr::new(
                seg[0], seg[1], seg[2], seg[3], seg[4], seg[5], seg[6], seg[7],
            )
            .to_string()
        } else {
            std::net::Ipv4Addr::new(
                self.dst_addr[0],
                self.dst_addr[1],
                self.dst_addr[2],
                self.dst_addr[3],
            )
            .to_string()
        }
    }

    /// Map a decoded kernel event to the daemon's upcall record. `fd` is supplied
    /// separately by the loader (the RingBuf event carries identity, not the fd).
    pub fn to_upcall(&self, fd: Option<RawFd>) -> KernelUpcall {
        KernelUpcall {
            socket_id: self.cookie,
            local_port: self.src_port,
            remote_port: self.dst_port,
            remote_addr: self.dst_addr_string(),
            cgroup_id: Some(self.cgroup_id),
            pid: None,
            fd,
        }
    }
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

/// Availability posture when the control plane's status changes.
///
/// This is the confidentiality-preserving replacement for a "Kinetic" plaintext
/// bypass. There is deliberately **no `Plaintext` variant**: cleartext egress is
/// unrepresentable, so no code path — and no future edit — can route mission
/// traffic in the clear. Availability under a daemon outage / EW jamming is
/// preserved by an *encrypted* PSK fallback, or else by dropping the connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AvailabilityPosture {
    /// Control plane healthy: full hybrid PQC handshake (forward secret).
    FullPqc,
    /// Control plane down but a fallback PSK is configured: quantum-safe
    /// AES-256-GCM under the PSK. Encrypted, authenticated, no forward secrecy.
    EncryptedFallback,
    /// Control plane down and no PSK: drop the connection. Never plaintext.
    FailClosed,
}

/// Choose the posture from control-plane availability and PSK configuration.
/// `daemon_available` is whatever liveness signal the v2 control plane uses
/// (heartbeat, socket reachability); `psk_configured` is `resolve_fallback_psk`
/// having returned a key.
pub fn select_posture(daemon_available: bool, psk_configured: bool) -> AvailabilityPosture {
    match (daemon_available, psk_configured) {
        (true, _) => AvailabilityPosture::FullPqc,
        (false, true) => AvailabilityPosture::EncryptedFallback,
        (false, false) => AvailabilityPosture::FailClosed,
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

/// Run the hybrid handshake and return the established initiator session keys.
///
/// NOTE: this is a *local* two-party exchange (the daemon plays both roles with
/// its own identity). In a live deployment the daemon performs this exchange
/// with the **remote** peer over the eBPF-paused socket; that socket I/O wiring
/// is the remaining integration step. The returned keys are real and are what
/// gets bridged into kTLS.
pub fn run_local_handshake(suite: CipherSuite) -> Result<SessionKeys, KernelNativeError> {
    let identity = crypto::resolve_identity().map_err(KernelNativeError::Crypto)?;
    let engine = suite.engine();
    let (state, client_hello) = engine
        .begin_initiator(&identity)
        .map_err(KernelNativeError::Crypto)?;
    let (_server_keys, server_hello) = engine
        .respond(&identity, &client_hello)
        .map_err(KernelNativeError::Crypto)?;
    state
        .finish(&identity, &server_hello)
        .map_err(KernelNativeError::Crypto)
}

/// Back-compat probe used by tests: run the handshake, discard the keys.
pub fn execute_local_handshake_probe(suite: CipherSuite) -> Result<(), KernelNativeError> {
    run_local_handshake(suite).map(|_| ())
}

pub fn complete_kernel_upcall(upcall: &KernelUpcall) -> Result<(), KernelNativeError> {
    if classify_upcall(upcall) == EnforcementDecision::Ignore {
        return Ok(());
    }
    let suite = configured_suite()?;
    let fd = upcall.fd.ok_or(KernelNativeError::MissingSocketReference)?;
    let keys = run_local_handshake(suite)?;
    // Bridge the PQC session into kernel TLS. On any failure the socket is torn
    // down inside `bridge_session_to_ktls`, so cleartext can never escape.
    bridge_session_to_ktls(fd, &keys)
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

impl KtlsSecrets {
    /// Build kTLS secrets from a session's exported traffic material. The record
    /// sequence starts at 0 (a fresh kTLS socket).
    pub fn from_traffic_secret(s: &KtlsTrafficSecret) -> Self {
        KtlsSecrets {
            key: s.key,
            salt: s.salt,
            iv: s.iv,
            rec_seq: [0u8; KTLS_REC_SEQ_LEN],
        }
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
    // SAFETY: the probe creates its own throwaway socket; `setsockopt` only
    // reads the 3-byte "tls" buffer; the fd is closed exactly once before
    // returning on every path.
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
    // SAFETY: `setsockopt` only reads `ulp.len()` bytes from the live static
    // buffer; an invalid `fd` yields EBADF, handled as an error below.
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
    // SAFETY: `info` is a live, fully-initialized `#[repr(C)]` struct and the
    // length passed is exactly its size; the kernel only reads it. The transient
    // key copy inside it is zeroized immediately after, on every path.
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

/// Fail closed: tear the socket down so no cleartext can be read or written on
/// it after a failed kTLS setup. `shutdown(SHUT_RDWR)` unblocks any peer and
/// `close` releases the fd.
#[cfg(target_os = "linux")]
fn fail_closed_shutdown(fd: RawFd) {
    // SAFETY: the bridge owns `fd` at this point (ownership was transferred in
    // via `into_raw_fd`); it is shut down and closed exactly once, here, and
    // never used afterwards. Errors are irrelevant — the socket is being killed.
    unsafe {
        libc::shutdown(fd, libc::SHUT_RDWR);
        libc::close(fd);
    }
}

#[cfg(not(target_os = "linux"))]
fn fail_closed_shutdown(fd: RawFd) {
    // SAFETY: as above — sole owner, closed exactly once, never reused.
    unsafe {
        libc::close(fd);
    }
}

/// The PQC -> kTLS bridge: export the established session's traffic keys, pack
/// them into the kernel's `tls12_crypto_info_aes_gcm_256`, and install them on
/// `fd` for both directions. The exported key material is zeroized as the
/// `KtlsTrafficKeys` / `KtlsDuplexKeys` drop. On ANY failure the socket is shut
/// down and closed (fail closed) so plaintext cannot traverse it.
pub fn bridge_session_to_ktls(fd: RawFd, keys: &SessionKeys) -> Result<(), KernelNativeError> {
    let traffic = keys.export_ktls();
    let duplex = KtlsDuplexKeys {
        tx: KtlsSecrets::from_traffic_secret(&traffic.tx),
        rx: KtlsSecrets::from_traffic_secret(&traffic.rx),
    };
    // `traffic` and `duplex` both zeroize their key bytes on drop at end of scope.
    match install_ktls_keys(fd, &duplex) {
        Ok(()) => Ok(()),
        Err(e) => {
            fail_closed_shutdown(fd);
            Err(e)
        }
    }
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

    #[test]
    fn kernel_event_is_56_bytes_and_round_trips() {
        assert_eq!(KernelSockEvent::WIRE_LEN, 56);
        let mut src = [0u8; 16];
        src[..4].copy_from_slice(&[10, 0, 0, 7]);
        let mut dst = [0u8; 16];
        dst[..4].copy_from_slice(&[93, 184, 216, 34]);
        let ev = KernelSockEvent {
            cookie: 0xDEAD_BEEF_0000_0001,
            cgroup_id: 42,
            src_addr: src,
            dst_addr: dst,
            src_port: 51000,
            dst_port: 443,
            family: libc::AF_INET as u16,
            _pad: 0,
        };
        let decoded = KernelSockEvent::from_bytes(&ev.to_bytes()).unwrap();
        assert_eq!(decoded, ev);
        assert_eq!(decoded.dst_addr_string(), "93.184.216.34");

        let up = decoded.to_upcall(Some(7));
        assert_eq!(up.socket_id, ev.cookie);
        assert_eq!(up.remote_port, 443);
        assert_eq!(up.remote_addr, "93.184.216.34");
        assert_eq!(up.cgroup_id, Some(42));
        assert_eq!(up.fd, Some(7));
        assert_eq!(classify_upcall(&up), EnforcementDecision::Enforce);
    }

    #[test]
    fn kernel_event_rejects_short_buffer() {
        assert!(KernelSockEvent::from_bytes(&[0u8; 10]).is_none());
    }

    #[test]
    fn ipv6_destination_renders() {
        let mut dst = [0u8; 16];
        dst[0..2].copy_from_slice(&[0x20, 0x01]);
        dst[15] = 1;
        let ev = KernelSockEvent {
            cookie: 1,
            cgroup_id: 0,
            src_addr: [0u8; 16],
            dst_addr: dst,
            src_port: 1,
            dst_port: 443,
            family: libc::AF_INET6 as u16,
            _pad: 0,
        };
        assert_eq!(ev.dst_addr_string(), "2001::1");
    }
}
