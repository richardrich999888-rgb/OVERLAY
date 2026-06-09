//! Over-socket handshake integration tests (no live eBPF/kTLS kernel required).
//!
//! Drives the real X25519 + ML-KEM exchange across a `tokio` loopback pair with
//! two async tasks (a client control daemon and a server control daemon), then
//! verifies the kTLS handoff fails closed where no `tls` module is present.

#![cfg(target_os = "linux")]

use tokio::net::{TcpListener, TcpStream};

use syntriass_overlay::crypto::{derive_identity_public_keys, CipherSuite, IdentityMaterial};
use syntriass_overlay::kernel_native::{ktls_supported, KernelNativeError};
use syntriass_overlay::over_socket::{
    establish_and_bridge, initiator_handshake, responder_handshake, HandshakeRole, OverSocketError,
};

const SUITE: CipherSuite = CipherSuite::NistStandard768;

/// Two identities that trust each other (peer public key == the other's).
fn trusting_identities() -> (IdentityMaterial, IdentityMaterial) {
    let (ce, cm) = ([0x11u8; 32], [0x22u8; 32]);
    let (se, sm) = ([0x33u8; 32], [0x44u8; 32]);
    let (ce_pub, cm_pub) = derive_identity_public_keys(&ce, &cm).unwrap();
    let (se_pub, sm_pub) = derive_identity_public_keys(&se, &sm).unwrap();
    let client = IdentityMaterial::from_bytes(ce, cm, se_pub, sm_pub).unwrap();
    let server = IdentityMaterial::from_bytes(se, sm, ce_pub, cm_pub).unwrap();
    (client, server)
}

#[tokio::test]
async fn over_socket_handshake_has_zero_key_drift() {
    let (client_id, server_id) = trusting_identities();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        responder_handshake(&mut stream, &server_id, SUITE)
            .await
            .map(|k| k.export_ktls())
    });
    let client = tokio::spawn(async move {
        let mut stream = TcpStream::connect(addr).await.unwrap();
        initiator_handshake(&mut stream, &client_id, SUITE)
            .await
            .map(|k| k.export_ktls())
    });

    let c = client.await.unwrap().expect("client handshake");
    let s = server.await.unwrap().expect("server handshake");

    // Zero drift: the initiator's TX direction must equal the responder's RX
    // direction (and vice versa), key + salt + IV, bit-for-bit.
    assert_eq!(c.tx.key, s.rx.key, "c2s key drift");
    assert_eq!(c.tx.salt, s.rx.salt, "c2s salt drift");
    assert_eq!(c.tx.iv, s.rx.iv, "c2s IV drift");
    assert_eq!(c.rx.key, s.tx.key, "s2c key drift");
    assert_eq!(c.rx.salt, s.tx.salt, "s2c salt drift");
    assert_eq!(c.rx.iv, s.tx.iv, "s2c IV drift");

    // And the two directions are distinct keys (not a degenerate derivation).
    assert_ne!(c.tx.key, c.rx.key, "directional keys must differ");
}

#[tokio::test]
async fn establish_and_bridge_transitions_to_ktls_then_fails_closed() {
    let (client_id, server_id) = trusting_identities();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        establish_and_bridge(stream, &server_id, SUITE, HandshakeRole::Responder).await
    });
    let client = tokio::spawn(async move {
        let stream = TcpStream::connect(addr).await.unwrap();
        establish_and_bridge(stream, &client_id, SUITE, HandshakeRole::Initiator).await
    });

    let c = client.await.unwrap();
    let s = server.await.unwrap();

    if ktls_supported() {
        // The handshake completed and kTLS was installed on a capable kernel.
        assert!(c.is_ok(), "client bridge should succeed: {c:?}");
        assert!(s.is_ok(), "server bridge should succeed: {s:?}");
    } else {
        // Handshake completed (we reached the kTLS phase), but the install fails
        // with the infrastructure marker -> fail closed, socket dropped.
        assert!(
            matches!(
                c,
                Err(OverSocketError::Ktls(KernelNativeError::KtlsUnavailable))
            ),
            "expected kTLS-unavailable fail-closed on client, got {c:?}"
        );
        assert!(
            matches!(
                s,
                Err(OverSocketError::Ktls(KernelNativeError::KtlsUnavailable))
            ),
            "expected kTLS-unavailable fail-closed on server, got {s:?}"
        );
    }
}

#[tokio::test]
async fn malformed_handshake_frame_drops_cleanly() {
    // A peer that sends garbage instead of a valid ClientHello must cause the
    // responder to error out and drop the socket — never hang, never plaintext.
    let (_client_id, server_id) = trusting_identities();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        responder_handshake(&mut stream, &server_id, SUITE).await
    });

    // Connect and send a too-short, bogus length-prefixed frame, then close.
    use tokio::io::AsyncWriteExt;
    let mut bad = TcpStream::connect(addr).await.unwrap();
    bad.write_all(&7u32.to_be_bytes()).await.unwrap();
    bad.write_all(b"garbage").await.unwrap();
    bad.flush().await.unwrap();
    drop(bad);

    let res = server.await.unwrap();
    assert!(
        res.is_err(),
        "malformed ClientHello must error, got {res:?}"
    );
}
