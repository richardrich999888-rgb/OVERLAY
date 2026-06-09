//! End-to-end validation of the SCM_RIGHTS fd-passing bridge.
//!
//! Simulates the full v2 lifecycle without a live eBPF/kTLS kernel: a mock
//! injector (a background thread — the in-process stand-in for a separate
//! injection process, exercising the identical `SCM_RIGHTS` syscalls) hands a
//! live TCP socket fd to the daemon side across a Unix domain socket. The daemon
//! takes ownership, runs the over-socket PQC handshake across the passed socket,
//! and reaches the kTLS gate — which fails closed here (no `tls` module).

#![cfg(target_os = "linux")]

use std::os::unix::io::{FromRawFd, IntoRawFd};

use tokio::net::TcpStream;

use syntriass_overlay::crypto::{derive_identity_public_keys, CipherSuite, IdentityMaterial};
use syntriass_overlay::fd_passing::{recv_fd, send_fd};
use syntriass_overlay::kernel_native::{ktls_supported, KernelNativeError};
use syntriass_overlay::over_socket::{establish_and_bridge, HandshakeRole, OverSocketError};

const SUITE: CipherSuite = CipherSuite::NistStandard768;

fn trusting_identities() -> (IdentityMaterial, IdentityMaterial) {
    let (ce, cm) = ([0x11u8; 32], [0x22u8; 32]);
    let (se, sm) = ([0x33u8; 32], [0x44u8; 32]);
    let (ce_pub, cm_pub) = derive_identity_public_keys(&ce, &cm).unwrap();
    let (se_pub, sm_pub) = derive_identity_public_keys(&se, &sm).unwrap();
    let client = IdentityMaterial::from_bytes(ce, cm, se_pub, sm_pub).unwrap();
    let server = IdentityMaterial::from_bytes(se, sm, ce_pub, cm_pub).unwrap();
    (client, server)
}

fn uds_socketpair() -> (i32, i32) {
    let mut sp = [0i32; 2];
    let rc = unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, sp.as_mut_ptr()) };
    assert_eq!(rc, 0, "socketpair failed");
    (sp[0], sp[1])
}

#[tokio::test]
async fn injected_fd_completes_handshake_and_reaches_ktls_gate() {
    let (client_id, server_id) = trusting_identities();

    // A real loopback TCP connection. The SERVER end's fd is what gets injected.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let client_std = std::net::TcpStream::connect(addr).unwrap();
    let (server_std, _) = listener.accept().unwrap();
    let server_fd = server_std.into_raw_fd();

    let (inj, dae) = uds_socketpair();

    // Mock injector: pass the server fd across the UDS, then close its copies.
    let injector = std::thread::spawn(move || {
        send_fd(inj, b"inject", server_fd).expect("send_fd");
        unsafe {
            libc::close(server_fd);
            libc::close(inj);
        }
    });

    // Daemon side: receive the fd (blocking recvmsg off the async runtime).
    let (_data, maybe_fd) = tokio::task::spawn_blocking(move || {
        let r = recv_fd(dae);
        unsafe { libc::close(dae) };
        r
    })
    .await
    .unwrap()
    .unwrap();
    injector.join().unwrap();
    let got_fd = maybe_fd.expect("daemon must receive the injected fd via SCM_RIGHTS");

    // Bind both ends into Tokio and drive the over-socket handshake + kTLS gate.
    let server_owned = unsafe { std::net::TcpStream::from_raw_fd(got_fd) };
    server_owned.set_nonblocking(true).unwrap();
    let server_stream = TcpStream::from_std(server_owned).unwrap();
    client_std.set_nonblocking(true).unwrap();
    let client_stream = TcpStream::from_std(client_std).unwrap();

    let server = tokio::spawn(async move {
        establish_and_bridge(server_stream, &server_id, SUITE, HandshakeRole::Responder).await
    });
    let client = tokio::spawn(async move {
        establish_and_bridge(client_stream, &client_id, SUITE, HandshakeRole::Initiator).await
    });
    let s = server.await.unwrap();
    let c = client.await.unwrap();

    if ktls_supported() {
        assert!(
            s.is_ok(),
            "server bridge should succeed on a kTLS host: {s:?}"
        );
        assert!(
            c.is_ok(),
            "client bridge should succeed on a kTLS host: {c:?}"
        );
    } else {
        // The handshake ran across the *passed* socket and reached the kTLS gate,
        // which fails closed without a tls module.
        assert!(
            matches!(
                s,
                Err(OverSocketError::Ktls(KernelNativeError::KtlsUnavailable))
            ),
            "server should reach kTLS gate then fail closed: {s:?}"
        );
        assert!(
            matches!(
                c,
                Err(OverSocketError::Ktls(KernelNativeError::KtlsUnavailable))
            ),
            "client should reach kTLS gate then fail closed: {c:?}"
        );
    }
}

#[tokio::test]
async fn missing_descriptor_fails_closed() {
    let (inj, dae) = uds_socketpair();

    // Send plain data with NO SCM_RIGHTS ancillary control message.
    std::thread::spawn(move || {
        let msg = b"no-fd-here";
        unsafe {
            libc::send(inj, msg.as_ptr() as *const libc::c_void, msg.len(), 0);
            libc::close(inj);
        }
    });

    let (data, maybe_fd) = tokio::task::spawn_blocking(move || {
        let r = recv_fd(dae);
        unsafe { libc::close(dae) };
        r
    })
    .await
    .unwrap()
    .unwrap();

    assert_eq!(data, b"no-fd-here");
    assert!(
        maybe_fd.is_none(),
        "no descriptor -> the daemon aborts the channel (fail closed), never proceeds"
    );
}
