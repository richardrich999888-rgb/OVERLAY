//! Real kTLS round-trip integration test.
//!
//! Installs TLS 1.3 AES-256-GCM keys via `setsockopt(SOL_TLS, TLS_TX|TLS_RX)`
//! on a loopback TCP pair and proves the *kernel* encrypts on one end and
//! decrypts on the other — i.e. the v2 kTLS data-plane primitive actually works,
//! not just compiles.
//!
//! On kernels without the TLS ULP (common in CI sandboxes / minimal containers)
//! the test skips cleanly instead of failing: kTLS support is an environment
//! property, not a code defect.

#![cfg(target_os = "linux")]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::io::AsRawFd;

use syntriass_overlay::kernel_native::{
    install_ktls_duplex, ktls_supported, KtlsDuplexKeys, KtlsSecrets, KTLS_IV_LEN, KTLS_KEY_LEN,
    KTLS_REC_SEQ_LEN, KTLS_SALT_LEN,
};

/// Deterministic per-direction key material. The two peers must agree on each
/// direction (A.tx == B.rx and A.rx == B.tx); identical struct contents on both
/// sides make the kernel derive matching AEAD nonces.
fn secrets(seed: u8) -> KtlsSecrets {
    KtlsSecrets {
        key: [seed; KTLS_KEY_LEN],
        salt: [seed ^ 0x5a; KTLS_SALT_LEN],
        iv: [seed ^ 0x33; KTLS_IV_LEN],
        rec_seq: [0u8; KTLS_REC_SEQ_LEN], // fresh connection -> sequence starts at 0
    }
}

fn loopback_pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let addr = listener.local_addr().expect("local addr");
    let client = TcpStream::connect(addr).expect("connect");
    let (server, _) = listener.accept().expect("accept");
    client.set_nodelay(true).ok();
    server.set_nodelay(true).ok();
    (client, server)
}

#[test]
fn ktls_loopback_roundtrip_or_skip() {
    if !ktls_supported() {
        eprintln!(
            "SKIP: kernel TLS (kTLS) ULP unavailable in this environment; \
             kTLS install code is compiled and unit-checked but the encrypt/\
             decrypt round-trip needs a kernel with the `tls` module."
        );
        return;
    }

    let (client, server) = loopback_pair();

    // c2s and s2c directions use distinct keys.
    let c2s = secrets(0xC2);
    let s2c = secrets(0x52);

    let client_keys = KtlsDuplexKeys {
        tx: c2s.clone(), // client encrypts c2s
        rx: s2c.clone(), // client decrypts s2c
    };
    let server_keys = KtlsDuplexKeys {
        tx: s2c.clone(), // server encrypts s2c
        rx: c2s.clone(), // server decrypts c2s
    };

    install_ktls_duplex(client.as_raw_fd(), &client_keys).expect("client kTLS install");
    install_ktls_duplex(server.as_raw_fd(), &server_keys).expect("server kTLS install");

    // client -> server: the kernel encrypts on write, decrypts on read.
    let c2s_msg = b"SYNTRIASS-KTLS-KERNEL-ENCRYPTED-C2S";
    (&client).write_all(c2s_msg).expect("client write");
    (&client).flush().ok();
    let mut got = vec![0u8; c2s_msg.len()];
    (&server).read_exact(&mut got).expect("server read");
    assert_eq!(&got, c2s_msg, "client->server kTLS round-trip");

    // server -> client: exercises the RX install on the client side too.
    let s2c_msg = b"SYNTRIASS-KTLS-ACK-FROM-KERNEL-S2C";
    (&server).write_all(s2c_msg).expect("server write");
    (&server).flush().ok();
    let mut back = vec![0u8; s2c_msg.len()];
    (&client).read_exact(&mut back).expect("client read");
    assert_eq!(&back, s2c_msg, "server->client kTLS round-trip");
}
