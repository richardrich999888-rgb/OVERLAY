//! Kernel-bridge verification harness (v2 split-plane).
//!
//! Exercises the full user-space path that the eBPF RingBuf would drive:
//!   1. decode a (mocked) kernel connection event into a daemon upcall;
//!   2. run the hybrid PQC handshake to get session keys;
//!   3. bridge those keys into kernel TLS via `setsockopt`.
//!
//! The eBPF emit side and the live kTLS encrypt/decrypt require an eBPF-capable
//! kernel + the `tls` module, neither of which exists in CI sandboxes — so the
//! "install succeeds" branch runs only where `ktls_supported()`, and everywhere
//! else we assert the **fail-closed** contract: the bridge returns an error AND
//! tears the socket down (shutdown + close) so no cleartext can traverse it.

#![cfg(target_os = "linux")]

use std::net::{TcpListener, TcpStream};
use std::os::unix::io::IntoRawFd;

use syntriass_overlay::crypto::{
    derive_fallback_session, SessionKeys, FALLBACK_NONCE_LEN, FALLBACK_PSK_LEN,
};
use syntriass_overlay::kernel_native::{
    bridge_session_to_ktls, ktls_supported, KernelNativeError, KernelSockEvent,
};

/// Build a real `SessionKeys` without needing identity config. The bridge
/// exports/install s kTLS material identically regardless of whether the keys
/// came from the PQC handshake or the PSK fallback; the handshake path itself is
/// covered by the crypto and defense-scenario tests.
fn session_keys() -> SessionKeys {
    let psk = [0x33u8; FALLBACK_PSK_LEN];
    let cn = [0x1u8; FALLBACK_NONCE_LEN];
    let sn = [0x2u8; FALLBACK_NONCE_LEN];
    derive_fallback_session(&psk, &cn, &sn, true).expect("session keys")
}

fn loopback_pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    let client = TcpStream::connect(addr).expect("connect");
    let (server, _) = listener.accept().expect("accept");
    (client, server)
}

#[test]
fn mocked_connect_event_decodes_to_upcall() {
    // Simulate the eBPF sockops capture of an outbound connect to 127.0.0.1:8443.
    let mut dst = [0u8; 16];
    dst[..4].copy_from_slice(&[127, 0, 0, 1]);
    let ev = KernelSockEvent {
        cookie: 0x5151_5151,
        cgroup_id: 1234,
        src_addr: [0u8; 16],
        dst_addr: dst,
        src_port: 50001,
        dst_port: 8443,
        family: libc::AF_INET as u16,
        _pad: 0,
    };

    // Round-trips through the exact binary layout the RingBuf carries.
    let decoded = KernelSockEvent::from_bytes(&ev.to_bytes()).expect("decode RingBuf record");
    assert_eq!(decoded, ev);

    let upcall = decoded.to_upcall(Some(11));
    assert_eq!(upcall.socket_id, 0x5151_5151);
    assert_eq!(upcall.remote_addr, "127.0.0.1");
    assert_eq!(upcall.remote_port, 8443);
    assert_eq!(upcall.cgroup_id, Some(1234));
    assert_eq!(upcall.fd, Some(11));
}

#[test]
fn handshake_then_ktls_bridge_installs_or_fails_closed() {
    // 1+2: established session keys (see `session_keys` note).
    let keys = session_keys();

    // 3: bridge onto a real connected TCP socket. Transfer fd ownership to the
    // bridge so there is no double-close with the TcpStream.
    let (client, _server) = loopback_pair();
    let fd = client.into_raw_fd();

    let result = bridge_session_to_ktls(fd, &keys);

    if ktls_supported() {
        assert!(
            result.is_ok(),
            "kTLS install must succeed on a kTLS-capable kernel: {result:?}"
        );
        // Socket stays open with kTLS active; close it to avoid leaking the fd.
        unsafe {
            libc::close(fd);
        }
    } else {
        // Fail-closed contract: an error is returned (ENOPROTOOPT/ENOENT class)
        // AND the socket fd has been shut down + closed so cleartext cannot flow.
        assert!(
            matches!(
                result,
                Err(KernelNativeError::KtlsUnavailable) | Err(KernelNativeError::Ktls(_))
            ),
            "expected a kTLS error, got {result:?}"
        );
        let probe = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        assert_eq!(probe, -1, "fail-closed must have closed the socket fd");
        let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        assert_eq!(errno, libc::EBADF, "closed fd must report EBADF");
    }
}

#[test]
fn ignored_event_is_not_enforced() {
    // A port-0 event (e.g. a listening/unbound socket) must be ignored, not
    // enforced — `complete_kernel_upcall` returns Ok without touching kTLS.
    let upcall = KernelSockEvent {
        cookie: 1,
        cgroup_id: 0,
        src_addr: [0u8; 16],
        dst_addr: [0u8; 16],
        src_port: 0,
        dst_port: 0,
        family: libc::AF_INET as u16,
        _pad: 0,
    }
    .to_upcall(None);
    assert!(syntriass_overlay::kernel_native::complete_kernel_upcall(&upcall).is_ok());
}
