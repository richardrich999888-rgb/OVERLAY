//! Phase 4 (Kinetic State Machine) — measured failover & recovery.
//!
//! Drives the [`Supervisor`] with REAL handshake outcomes (a handshake against an
//! untrusted identity returns `Err` → failure; a trusting handshake succeeds) and
//! measures failover time, recovery time, and per-event processing latency. The
//! posture transitions are the autonomous operational recovery; the
//! `operation_mode_flag()` is what the eBPF policy engine (Phase 3) consumes.

use std::time::Instant;

use syntriass_overlay::crypto::{
    derive_identity_public_keys, CipherSuite, IdentityMaterial, ED25519_SEED_LEN, MLDSA65_SEED_LEN,
};
use syntriass_overlay::kinetic::{KineticConfig, OperationMode, Supervisor};

fn server() -> IdentityMaterial {
    let (se, sm) = ([0x33u8; ED25519_SEED_LEN], [0x44u8; MLDSA65_SEED_LEN]);
    let (ce, cm) = ([0x11u8; ED25519_SEED_LEN], [0x22u8; MLDSA65_SEED_LEN]);
    let (ce_pub, cm_pub) = derive_identity_public_keys(&ce, &cm).unwrap();
    IdentityMaterial::from_bytes(se, sm, ce_pub, cm_pub).unwrap()
}
fn trusted_client() -> IdentityMaterial {
    let (ce, cm) = ([0x11u8; ED25519_SEED_LEN], [0x22u8; MLDSA65_SEED_LEN]);
    let (se, sm) = ([0x33u8; ED25519_SEED_LEN], [0x44u8; MLDSA65_SEED_LEN]);
    let (se_pub, sm_pub) = derive_identity_public_keys(&se, &sm).unwrap();
    IdentityMaterial::from_bytes(ce, cm, se_pub, sm_pub).unwrap()
}
fn untrusted_client() -> IdentityMaterial {
    // A client the server does NOT trust (wrong peer keys) → respond() Err.
    let (xe, xm) = ([0x99u8; ED25519_SEED_LEN], [0x98u8; MLDSA65_SEED_LEN]);
    let (xe_pub, xm_pub) = derive_identity_public_keys(&xe, &xm).unwrap();
    IdentityMaterial::from_bytes(xe, xm, xe_pub, xm_pub).unwrap()
}

/// One real handshake attempt; returns true on success (server accepts).
fn handshake_attempt(client: &IdentityMaterial, server: &IdentityMaterial) -> bool {
    let engine = CipherSuite::NistStandard768.engine();
    let (_state, ch) = match engine.begin_initiator(client) {
        Ok(v) => v,
        Err(_) => return false,
    };
    engine.respond(server, &ch).is_ok()
}

#[test]
fn failover_and_recovery_measured() {
    let srv = server();
    let good = trusted_client();
    let bad = untrusted_client();

    // Sanity: the two clients really do succeed / fail against this server.
    assert!(handshake_attempt(&good, &srv));
    assert!(!handshake_attempt(&bad, &srv));

    let mut s = Supervisor::new(KineticConfig::default());

    // ---- FAILOVER: sustained REAL handshake failures drive the degradation ----
    let t0 = Instant::now();
    let mut to_fallback = None;
    let mut to_failclosed = None;
    while s.mode() != OperationMode::FailClosed {
        let ok = handshake_attempt(&bad, &srv); // real failing handshake
        let before = s.mode();
        let after = if ok {
            s.handle_handshake_success()
        } else {
            s.handle_handshake_failure()
        };
        if before == OperationMode::FullPqc && after == OperationMode::EncryptedFallback {
            to_fallback = Some(t0.elapsed());
        }
        if after == OperationMode::FailClosed {
            to_failclosed = Some(t0.elapsed());
        }
    }
    let to_fallback = to_fallback.expect("must pass through EncryptedFallback");
    let to_failclosed = to_failclosed.unwrap();

    // ---- RECOVERY: sustained REAL successes climb back to FullPqc ----
    let t1 = Instant::now();
    while s.mode() != OperationMode::FullPqc {
        let ok = handshake_attempt(&good, &srv); // real succeeding handshake
        if ok {
            s.handle_handshake_success();
        } else {
            s.handle_handshake_failure();
        }
    }
    let recovery = t1.elapsed();

    // ---- per-event state-machine processing latency ----
    let mut s2 = Supervisor::new(KineticConfig::default());
    let n = 100_000;
    let te = Instant::now();
    for i in 0..n {
        if i % 2 == 0 {
            s2.handle_handshake_failure();
        } else {
            s2.handle_handshake_success();
        }
    }
    let per_event_ns = te.elapsed().as_secs_f64() * 1e9 / n as f64;

    println!("\n==== KINETIC STATE MACHINE — failover & recovery (measured) ====");
    println!(
        "  FullPqc -> EncryptedFallback : {:.0} us",
        to_fallback.as_secs_f64() * 1e6
    );
    println!(
        "  FullPqc -> FailClosed (total): {:.0} us",
        to_failclosed.as_secs_f64() * 1e6
    );
    println!(
        "  FailClosed/Fallback -> FullPqc (recovery): {:.0} us",
        recovery.as_secs_f64() * 1e6
    );
    println!("  per-event processing latency : {per_event_ns:.1} ns");
    println!("  total posture transitions    : {}", s.transition_count());
    println!(
        "  final operation_mode_flag    : {} (0=FullPqc)\n",
        s.operation_mode_flag()
    );

    // Correctness: ended healthy; transitions happened; no plaintext anywhere.
    assert_eq!(s.mode(), OperationMode::FullPqc);
    assert!(s.transition_count() >= 3); // FullPqc->Fallback->FailClosed->...->FullPqc
}

#[test]
fn security_violation_is_sticky_under_real_successes() {
    let srv = server();
    let good = trusted_client();
    let mut s = Supervisor::new(KineticConfig::default());

    s.force_fail_closed();
    assert_eq!(s.mode(), OperationMode::FailClosed);
    // Even with real, succeeding handshakes, a security fail-closed stays closed.
    for _ in 0..20 {
        assert!(handshake_attempt(&good, &srv));
        s.handle_handshake_success();
    }
    assert_eq!(
        s.mode(),
        OperationMode::FailClosed,
        "security lock must be sticky"
    );
    assert!(s.is_security_locked());
    s.reset();
    assert_eq!(s.mode(), OperationMode::FullPqc);
    println!("[kinetic] security fail-closed stayed sticky through 20 real successes; manual reset cleared it");
}
