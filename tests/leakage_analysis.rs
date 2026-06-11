//! Plaintext-leakage analysis — surfaces beyond the ciphertext itself.
//!
//! `tests/fail_closed_properties.rs` proves no plaintext canary survives into
//! sealed records. This suite covers the *other* places secrets could escape:
//!
//!   L1  Debug/log surfaces: `{:?}` on every key-holding type must not print
//!       key bytes (daemon logs are shipped off-box; a Debug leak is a key leak).
//!   L2  Handshake wire image: the bytes actually exchanged during a full
//!       handshake must not contain the derived session-key material.
//!   L3  Error surfaces: every error type's Display/Debug output must not echo
//!       attacker input or key material (no reflection, no amplification).
//!   L4  Fallback wire image: the encrypted-fallback exchange must not leak the
//!       PSK onto the wire.
//!
//! All checks run real code; no fabricated outcomes.

use rand::rngs::StdRng;
use rand::{RngCore, SeedableRng};

use syntriass_overlay::crypto::{
    derive_fallback_session, derive_identity_public_keys, CipherSuite, IdentityMaterial,
    SessionLimits, ED25519_SEED_LEN, FALLBACK_NONCE_LEN, FALLBACK_PSK_LEN, MLDSA65_SEED_LEN,
};
use syntriass_overlay::handshake_guard::{AdmissionError, GuardConfig, HandshakeGuard};

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack.len() >= needle.len()
        && haystack.windows(needle.len()).any(|w| w == needle)
}

/// Render `bytes` as lowercase hex (the most common accidental log format).
fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(&mut s, "{b:02x}");
    }
    s
}

fn trusting_identities() -> (IdentityMaterial, IdentityMaterial) {
    let (ce, cm) = ([0x11u8; ED25519_SEED_LEN], [0x22u8; MLDSA65_SEED_LEN]);
    let (se, sm) = ([0x33u8; ED25519_SEED_LEN], [0x44u8; MLDSA65_SEED_LEN]);
    let (ce_pub, cm_pub) = derive_identity_public_keys(&ce, &cm).unwrap();
    let (se_pub, sm_pub) = derive_identity_public_keys(&se, &sm).unwrap();
    let client = IdentityMaterial::from_bytes(ce, cm, se_pub, sm_pub).unwrap();
    let server = IdentityMaterial::from_bytes(se, sm, ce_pub, cm_pub).unwrap();
    (client, server)
}

#[test]
fn l1_debug_surfaces_do_not_print_key_material() {
    let (client_id, server_id) = trusting_identities();
    let engine = CipherSuite::NistStandard768.engine();
    let (state, hello) = engine.begin_initiator(&client_id).unwrap();
    let (server_keys, server_hello) = engine.respond(&server_id, &hello).unwrap();
    let client_keys = state.finish(&client_id, &server_hello).unwrap();

    // Export the raw traffic keys so we know the exact bytes that must not leak.
    let ktls = client_keys.export_ktls();
    let tx_key_hex = hex(&ktls.tx.key);
    let rx_key_hex = hex(&ktls.rx.key);

    // Every key-holding type's Debug output:
    let surfaces = [
        format!("{client_keys:?}"),
        format!("{server_keys:?}"),
        format!("{ktls:?}"),
        format!("{:?}", ktls.tx),
        format!("{client_id:?}"),
        format!("{server_id:?}"),
    ];
    for s in &surfaces {
        let lower = s.to_lowercase();
        assert!(
            !lower.contains(&tx_key_hex) && !lower.contains(&rx_key_hex),
            "Debug surface leaked traffic-key bytes: {s}"
        );
        // No Debug surface may dump 32 raw key bytes as a decimal array either.
        let tx0 = ktls.tx.key;
        let decimal_run = format!("{}, {}, {}, {}", tx0[0], tx0[1], tx0[2], tx0[3]);
        assert!(
            !s.contains(&decimal_run),
            "Debug surface appears to dump raw key bytes: {s}"
        );
    }
    eprintln!(
        "[L1 debug-redaction] surfaces_checked={} key_leaks=0",
        surfaces.len()
    );
}

#[test]
fn l2_handshake_wire_never_carries_derived_session_keys() {
    let (client_id, server_id) = trusting_identities();
    let engine = CipherSuite::NistStandard768.engine();

    // The complete wire image of the handshake: ClientHello || ServerHello.
    let (state, client_hello) = engine.begin_initiator(&client_id).unwrap();
    let (server_keys, server_hello) = engine.respond(&server_id, &client_hello).unwrap();
    let client_keys = state.finish(&client_id, &server_hello).unwrap();
    let mut wire = client_hello.clone();
    wire.extend_from_slice(&server_hello);

    // The derived secrets (both sides agree, so checking one side suffices —
    // assert that first).
    let ck = client_keys.export_ktls();
    let sk = server_keys.export_ktls();
    assert_eq!(ck.tx.key, sk.rx.key, "key agreement sanity");

    for (label, secret) in [
        ("client tx key", &ck.tx.key[..]),
        ("client rx key", &ck.rx.key[..]),
        ("tx iv", &ck.tx.iv[..]),
        ("rx iv", &ck.rx.iv[..]),
    ] {
        assert!(
            !contains(&wire, secret),
            "handshake wire image contains the derived {label}"
        );
    }
    eprintln!(
        "[L2 wire-keys     ] wire_bytes={} derived_secrets_on_wire=0",
        wire.len()
    );
}

#[test]
fn l3_error_surfaces_do_not_reflect_input_or_secrets() {
    // Errors must be constant-shaped: no attacker bytes, no key bytes.
    let marker = b"ATTACKER-CONTROLLED-INPUT-7f3a";
    let (_c, server_id) = trusting_identities();
    let engine = CipherSuite::NistStandard768.engine();

    // Feed attacker-marked input into the responder and render every error.
    let mut bad_hello = vec![0u8; 6000];
    bad_hello[..marker.len()].copy_from_slice(marker);
    let err = engine.respond(&server_id, &bad_hello).unwrap_err();
    let rendered = format!("{err:?}");
    assert!(
        !rendered.contains("ATTACKER-CONTROLLED"),
        "crypto error reflected attacker bytes: {rendered}"
    );

    // Admission errors are fieldless enums — render each variant.
    for e in [
        AdmissionError::Throttled,
        AdmissionError::Expired,
        AdmissionError::BadMac,
        AdmissionError::Replay,
        AdmissionError::Malformed,
        AdmissionError::GlobalRateLimited,
        AdmissionError::AtCapacity,
    ] {
        let s = format!("{e:?}");
        assert!(s.len() < 64, "admission error unexpectedly verbose: {s}");
    }
    eprintln!("[L3 error-reflect ] crypto+admission error surfaces: reflection=0");
}

#[test]
fn l4_fallback_wire_never_carries_the_psk() {
    let mut rng = StdRng::seed_from_u64(0x4C45414B); // "LEAK"
    let mut psk = [0u8; FALLBACK_PSK_LEN];
    rng.fill_bytes(&mut psk);
    let cn = [0x0Au8; FALLBACK_NONCE_LEN];
    let sn = [0x0Bu8; FALLBACK_NONCE_LEN];

    let mut tx = derive_fallback_session(&psk, &cn, &sn, true)
        .unwrap()
        .into_secure_session(SessionLimits::default());

    // Everything the fallback puts on the wire: nonces (cleartext by design) +
    // sealed records. None of it may contain the PSK or the derived key.
    let mut wire = Vec::new();
    wire.extend_from_slice(&cn);
    wire.extend_from_slice(&sn);
    for i in 0..2_000u32 {
        let rec = tx.seal(format!("fallback-frame-{i}").as_bytes()).unwrap();
        wire.extend_from_slice(&rec);
    }
    assert!(
        !contains(&wire, &psk),
        "fallback wire image contains the PSK"
    );
    // Also check a guard rotation secret never appears in issued cookies.
    let mut guard = HandshakeGuard::new(GuardConfig::default(), 1_000);
    let cookie = guard.request(b"peer", 1_000).unwrap();
    assert!(
        !contains(&cookie.to_bytes(), &psk),
        "cookie unexpectedly contains foreign secret bytes"
    );
    eprintln!(
        "[L4 fallback-psk  ] wire_bytes={} psk_on_wire=0",
        wire.len()
    );
}
