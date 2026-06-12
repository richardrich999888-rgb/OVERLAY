//! Phase 2 (PQC → kTLS secret bridge) — the validatable parts.
//!
//! Real kernel TLS (the `tls` ULP) is **not available** in this environment (no
//! `tls` module; `kernel_native::ktls_supported()` is false), so the kTLS
//! encrypt/decrypt round-trip and the throughput benchmark cannot run here — they
//! are `[design]` with a host-side plan (`docs/KTLS_INTEGRATION.md`). What IS
//! validated here, without the kernel ULP:
//!   * the kTLS traffic secrets are **derived from the PQC handshake** and agree
//!     between peers (initiator TX == responder RX, both directions);
//!   * the secrets pack into the kernel `tls12_crypto_info_aes_gcm_256` material;
//!   * the bridge **fails closed** on a kernel with no TLS ULP.

#![cfg(target_os = "linux")]

use std::os::unix::io::IntoRawFd;

use syntriass_overlay::crypto::{
    derive_identity_public_keys, CipherSuite, IdentityMaterial, ED25519_SEED_LEN, MLDSA65_SEED_LEN,
};
use syntriass_overlay::kernel_native::{bridge_session_to_ktls, ktls_supported, KtlsSecrets};

fn trusting() -> (IdentityMaterial, IdentityMaterial) {
    let (ce, cm) = ([0x11u8; ED25519_SEED_LEN], [0x22u8; MLDSA65_SEED_LEN]);
    let (se, sm) = ([0x33u8; ED25519_SEED_LEN], [0x44u8; MLDSA65_SEED_LEN]);
    let (ce_pub, cm_pub) = derive_identity_public_keys(&ce, &cm).unwrap();
    let (se_pub, sm_pub) = derive_identity_public_keys(&se, &sm).unwrap();
    let client = IdentityMaterial::from_bytes(ce, cm, se_pub, sm_pub).unwrap();
    let server = IdentityMaterial::from_bytes(se, sm, ce_pub, cm_pub).unwrap();
    (client, server)
}

#[test]
fn ktls_secrets_are_derived_from_pqc_handshake_and_agree() {
    let (client_id, server_id) = trusting();
    let engine = CipherSuite::NistStandard768.engine();
    let (state, ch) = engine.begin_initiator(&client_id).unwrap();
    let (server_keys, sh) = engine.respond(&server_id, &ch).unwrap();
    let client_keys = state.finish(&client_id, &sh).unwrap();

    let c = client_keys.export_ktls();
    let s = server_keys.export_ktls();

    // SUCCESS CRITERION: secrets derived from the PQC handshake, and each
    // direction agrees across the peers (initiator TX == responder RX).
    assert_eq!(c.tx.key, s.rx.key, "c2s key must agree");
    assert_eq!(c.rx.key, s.tx.key, "s2c key must agree");
    assert_eq!(c.tx.salt, s.rx.salt);
    assert_eq!(c.tx.iv, s.rx.iv);
    assert_eq!(c.rx.salt, s.tx.salt);
    assert_eq!(c.rx.iv, s.tx.iv);
    // Distinct directions use distinct keys.
    assert_ne!(c.tx.key, c.rx.key);
    // Correct lengths for AES-256-GCM TLS 1.3.
    assert_eq!(c.tx.key.len(), 32);
    assert_eq!(c.tx.salt.len(), 4);
    assert_eq!(c.tx.iv.len(), 8);
}

#[test]
fn traffic_secret_packs_into_kernel_crypto_info() {
    let (client_id, server_id) = trusting();
    let engine = CipherSuite::NistStandard768.engine();
    let (state, ch) = engine.begin_initiator(&client_id).unwrap();
    let (_server_keys, sh) = engine.respond(&server_id, &ch).unwrap();
    let client_keys = state.finish(&client_id, &sh).unwrap();
    let k = client_keys.export_ktls();

    let secrets = KtlsSecrets::from_traffic_secret(&k.tx);
    assert_eq!(secrets.key, k.tx.key, "key copied into kTLS material");
    assert_eq!(secrets.salt, k.tx.salt);
    assert_eq!(secrets.iv, k.tx.iv);
    assert_eq!(
        secrets.rec_seq, [0u8; 8],
        "fresh kTLS socket starts at record seq 0"
    );
}

#[test]
fn bridge_fails_closed_when_no_tls_ulp() {
    // This environment has no TLS ULP; the bridge must FAIL CLOSED (Err), tearing
    // the socket down rather than leaving an unprotected fd.
    if ktls_supported() {
        eprintln!("[skip] this kernel HAS the TLS ULP; fail-closed-no-ULP test is N/A");
        return;
    }
    let (client_id, server_id) = trusting();
    let engine = CipherSuite::NistStandard768.engine();
    let (state, ch) = engine.begin_initiator(&client_id).unwrap();
    let (_sk, sh) = engine.respond(&server_id, &ch).unwrap();
    let keys = state.finish(&client_id, &sh).unwrap();

    // A real connected loopback socket to hand to the bridge.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let client = std::net::TcpStream::connect(addr).unwrap();
    let (_accepted, _) = listener.accept().unwrap();
    let fd = client.into_raw_fd();

    let r = bridge_session_to_ktls(fd, &keys);
    assert!(
        r.is_err(),
        "with no TLS ULP the bridge MUST fail closed, got {r:?}"
    );
    eprintln!("[ktls bridge] no TLS ULP here -> bridge failed closed (socket torn down): {r:?}");
}
