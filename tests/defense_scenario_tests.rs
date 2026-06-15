//! Defense scenario tests.
//!
//! Test 1 (fault-injection stability) lives as a unit test in
//! `src/interceptor.rs::crash_isolation_tests` — it needs the crate-internal FFI
//! shields and lock helpers, and must NOT route through the `#[no_mangle]`
//! `recv`/`send` exports from a normal test binary (that would interpose libc
//! for the test process itself). Run it with `cargo test crash_isolation`.
//!
//! Test 2 (encrypted degraded fallback) lives here and uses only the public API.
//! It verifies the confidentiality-preserving replacement for a plaintext
//! "Kinetic" bypass: when the PQC control plane is unavailable, traffic either
//! stays ENCRYPTED (PSK fallback) or the connection is dropped — never cleartext.

use std::time::Instant;

use syntriass_overlay::crypto::{derive_fallback_session, FALLBACK_NONCE_LEN, FALLBACK_PSK_LEN};
use syntriass_overlay::kernel_native::{select_posture, AvailabilityPosture};

#[test]
fn posture_never_routes_plaintext() {
    // Availability is preserved by encryption or by dropping — never cleartext.
    assert_eq!(select_posture(true, false), AvailabilityPosture::FullPqc);
    assert_eq!(select_posture(true, true), AvailabilityPosture::FullPqc);
    assert_eq!(
        select_posture(false, true),
        AvailabilityPosture::EncryptedFallback,
        "daemon down + PSK => encrypted fallback (not plaintext)"
    );
    assert_eq!(
        select_posture(false, false),
        AvailabilityPosture::FailClosed,
        "daemon down + no PSK => drop (not plaintext)"
    );
    // There is no AvailabilityPosture::Plaintext variant by construction.
}

#[test]
fn degraded_fallback_channel_is_encrypted_and_authenticated() {
    let psk = [0x9bu8; FALLBACK_PSK_LEN];
    let client_nonce = [0x11u8; FALLBACK_NONCE_LEN];
    let server_nonce = [0x22u8; FALLBACK_NONCE_LEN];

    let mut client = derive_fallback_session(&psk, &client_nonce, &server_nonce, true).unwrap();
    let mut server = derive_fallback_session(&psk, &client_nonce, &server_nonce, false).unwrap();

    // Encrypts (ciphertext != plaintext) and round-trips both directions.
    let c2s = b"MISSION-TRAFFIC-UNDER-EW-JAMMING";
    let frame = client.seal(c2s).unwrap();
    assert_ne!(&frame[..], &c2s[..], "fallback must not emit plaintext");
    assert_eq!(server.open(&frame).unwrap(), c2s, "c2s fallback round-trip");

    let s2c = b"COMMAND-ACK";
    let back = server.seal(s2c).unwrap();
    assert_eq!(client.open(&back).unwrap(), s2c, "s2c fallback round-trip");

    // Implicit authentication: a peer without the PSK derives different keys and
    // cannot open the records (AEAD fails closed).
    let wrong_psk = [0x77u8; FALLBACK_PSK_LEN];
    let mut attacker =
        derive_fallback_session(&wrong_psk, &client_nonce, &server_nonce, false).unwrap();
    let secret = client.seal(b"classified").unwrap();
    assert!(
        attacker.open(&secret).is_err(),
        "wrong PSK must fail to decrypt (no unauthenticated access)"
    );
}

#[test]
fn fresh_nonces_change_the_fallback_keys() {
    // Different nonce pairs must yield non-interoperable sessions (the nonces are
    // folded into the key schedule), so a recorded session cannot be replayed
    // against a new one.
    let psk = [0x42u8; FALLBACK_PSK_LEN];
    let mut a = derive_fallback_session(
        &psk,
        &[1; FALLBACK_NONCE_LEN],
        &[2; FALLBACK_NONCE_LEN],
        true,
    )
    .unwrap();
    let mut b = derive_fallback_session(
        &psk,
        &[3; FALLBACK_NONCE_LEN],
        &[4; FALLBACK_NONCE_LEN],
        false,
    )
    .unwrap();
    let frame = a.seal(b"x").unwrap();
    assert!(
        b.open(&frame).is_err(),
        "different nonces must not interoperate"
    );
}

#[test]
fn switchover_decision_latency_is_measured() {
    // Honest, in-process control-plane latency: the posture decision PLUS the
    // fallback key derivation a real switch would perform. This is NOT the eBPF
    // kernel switchover (that data plane is not implemented and is not runnable
    // here), so it is reported as a control-plane number, not a kernel one.
    let psk = [0x5au8; FALLBACK_PSK_LEN];
    let cn = [0x3u8; FALLBACK_NONCE_LEN];
    let sn = [0x4u8; FALLBACK_NONCE_LEN];

    let iters = 2000;
    let mut max_ns: u128 = 0;
    let mut total_ns: u128 = 0;
    for _ in 0..iters {
        let t = Instant::now();
        if select_posture(false, true) == AvailabilityPosture::EncryptedFallback {
            let _ = derive_fallback_session(&psk, &cn, &sn, true).unwrap();
        }
        let e = t.elapsed().as_nanos();
        total_ns += e;
        if e > max_ns {
            max_ns = e;
        }
    }
    let mean_ns = total_ns / iters as u128;
    println!(
        "control-plane degraded-switch decision+derive: mean {mean_ns} ns, max {max_ns} ns ({iters} iters)"
    );
    // Generous ceiling so CI is not flaky; the point is a real, logged number.
    if std::env::var_os("SYNTRIASS_EMULATED").is_some() {
        // Under CPU emulation (qemu-user for the ARM64 run) a single iteration's
        // max can absorb a multi-ms translation pause; gate on the mean there.
        assert!(
            mean_ns < 2_000_000,
            "decision+derive mean must be well under 2 ms (emulated)"
        );
    } else {
        assert!(
            max_ns < 2_000_000,
            "decision+derive must be well under 2 ms"
        );
    }
}
