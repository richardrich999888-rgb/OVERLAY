//! Anti-DoS admission-gate validation against the **real** PQC responder
//! (mitigation for finding C6: handshake-flood CPU exhaustion).
//!
//! The "expensive work" an attacker tries to provoke is the genuine hybrid
//! responder `engine.respond()` — ML-KEM encapsulation + X25519 + ML-DSA-65
//! sign/verify. Every scenario below counts how many times that real operation
//! actually runs when traffic is forced through `HandshakeGuard`. The headline
//! property: **invalid / spoofed / replayed / malformed floods drive the PQC
//! responder zero times**, and a legitimate flood drives it only up to the
//! per-source rate budget — never once per attacker packet.
//!
//! No fabricated numbers: the printed counts are the real outcomes of the real
//! gate and the real responder in this run.

use syntriass_overlay::crypto::{
    CipherSuite, IdentityMaterial, ED25519_SEED_LEN, MLDSA65_SEED_LEN,
};
use syntriass_overlay::handshake_guard::{
    AdmissionError, Cookie, GuardConfig, HandshakeGuard, COOKIE_WIRE_LEN,
};

fn trusting_identities() -> (IdentityMaterial, IdentityMaterial) {
    let client_ed = [0x11u8; ED25519_SEED_LEN];
    let client_ml = [0x22u8; MLDSA65_SEED_LEN];
    let server_ed = [0x33u8; ED25519_SEED_LEN];
    let server_ml = [0x44u8; MLDSA65_SEED_LEN];
    let (client_ed_pub, client_ml_pub) =
        syntriass_overlay::crypto::derive_identity_public_keys(&client_ed, &client_ml).unwrap();
    let (server_ed_pub, server_ml_pub) =
        syntriass_overlay::crypto::derive_identity_public_keys(&server_ed, &server_ml).unwrap();
    let client = IdentityMaterial::from_bytes(client_ed, client_ml, server_ed_pub, server_ml_pub)
        .expect("client identity");
    let server = IdentityMaterial::from_bytes(server_ed, server_ml, client_ed_pub, client_ml_pub)
        .expect("server identity");
    (client, server)
}

/// A test harness that owns the guard, the real server identity, and a genuine
/// ClientHello, and *counts every real PQC responder invocation*.
struct Responder {
    guard: HandshakeGuard,
    server_id: IdentityMaterial,
    client_hello: Vec<u8>,
    pqc_invocations: u64,
}

impl Responder {
    fn new(cfg: GuardConfig, now: u64) -> Self {
        let (client_id, server_id) = trusting_identities();
        let engine = CipherSuite::NistStandard768.engine();
        let (_state, client_hello) = engine.begin_initiator(&client_id).expect("client hello");
        Self {
            guard: HandshakeGuard::new(cfg, now),
            server_id,
            client_hello,
            pqc_invocations: 0,
        }
    }

    /// The protected expensive path: only ever called after `admit` succeeds.
    fn run_real_pqc(&mut self) {
        let engine = CipherSuite::NistStandard768.engine();
        let _ = engine
            .respond(&self.server_id, &self.client_hello)
            .expect("genuine hello must complete");
        self.pqc_invocations += 1;
    }

    /// Full two-phase attempt for one (honest) connection: phase-0 request, then
    /// phase-1 admit, then — and only then — the real PQC work.
    fn honest_attempt(&mut self, source: &[u8], now: u64) -> Result<(), AdmissionError> {
        let cookie = self.guard.request(source, now)?;
        self.guard.admit(source, &cookie, now)?;
        self.run_real_pqc();
        Ok(())
    }

    /// An attacker who submits a phase-1 message directly (bypassing phase-0)
    /// with whatever cookie they could fabricate.
    fn attacker_admit(&mut self, source: &[u8], cookie: &Cookie, now: u64) {
        if self.guard.admit(source, cookie, now).is_ok() {
            self.run_real_pqc();
        }
    }
}

#[test]
fn legitimate_flood_is_capped_by_rate_budget_not_per_packet() {
    let cfg = GuardConfig {
        rate_capacity: 20,
        rate_refill_per_sec: 10,
        ..GuardConfig::default()
    };
    let mut r = Responder::new(cfg, 1_000);
    let src = b"203.0.113.7:40000";

    let attempts = 1_000u64;
    let mut completed = 0u64;
    let mut throttled = 0u64;
    for _ in 0..attempts {
        match r.honest_attempt(src, 1_000) {
            Ok(()) => completed += 1,
            Err(AdmissionError::Throttled) => throttled += 1,
            Err(e) => panic!("unexpected {e:?}"),
        }
    }

    // PQC ran exactly once per admitted connection, and admissions are capped at
    // the burst budget — NOT once per attacker packet.
    assert_eq!(r.pqc_invocations, completed);
    assert_eq!(
        completed, 20,
        "served exactly the burst capacity in one second"
    );
    assert_eq!(throttled, attempts - 20);
    eprintln!(
        "[legit flood ] attempts={attempts} pqc_invocations={} throttled={throttled}",
        r.pqc_invocations
    );
}

#[test]
fn invalid_handshake_flood_triggers_zero_pqc() {
    let mut r = Responder::new(GuardConfig::default(), 1_000);
    // 50k phase-1 messages carrying forged cookies the server never issued.
    let flood = 50_000u64;
    for i in 0..flood {
        let forged = Cookie {
            issued_at: 1_000,
            server_nonce: [(i & 0xff) as u8; 16],
            mac: [(i >> 8) as u8; 32],
        };
        r.attacker_admit(b"attacker", &forged, 1_000);
    }
    assert_eq!(
        r.pqc_invocations, 0,
        "forged-cookie flood must never reach the PQC responder"
    );
    let (_issued, admitted, rejected) = r.guard.counters();
    assert_eq!(admitted, 0);
    assert_eq!(rejected, flood);
    eprintln!("[invalid flood] forged={flood} pqc_invocations=0 rejected={rejected}");
}

#[test]
fn spoofed_source_flood_triggers_zero_pqc() {
    // An attacker spoofing source addresses cannot receive the cookie reply, so
    // can never produce a valid phase-1 message. Model: each spoofed source sends
    // a phase-1 with a fabricated cookie. None reach PQC; the source map stays
    // bounded by the configured cap.
    let cfg = GuardConfig {
        max_sources: 256,
        ..GuardConfig::default()
    };
    let mut r = Responder::new(cfg, 1_000);
    for i in 0..20_000u32 {
        let src = format!("198.51.100.{}:{}", i % 256, i);
        let forged = Cookie {
            issued_at: 1_000,
            server_nonce: [0; 16],
            mac: [i as u8; 32],
        };
        r.attacker_admit(src.as_bytes(), &forged, 1_000);
    }
    assert_eq!(r.pqc_invocations, 0);
    eprintln!("[spoof  flood] spoofed_sources=20000 pqc_invocations=0");
}

#[test]
fn replayed_handshake_triggers_pqc_at_most_once() {
    let mut r = Responder::new(GuardConfig::default(), 1_000);
    let src = b"replayer";
    // Obtain one genuine cookie, then replay the phase-1 message many times.
    let cookie = r.guard.request(src, 1_000).unwrap();
    let replays = 10_000u64;
    let mut first = true;
    let mut replay_rejections = 0u64;
    for _ in 0..replays {
        match r.guard.admit(src, &cookie, 1_000) {
            Ok(()) => {
                assert!(first, "a replayed cookie was admitted twice");
                first = false;
                r.run_real_pqc();
            }
            Err(AdmissionError::Replay) => replay_rejections += 1,
            Err(e) => panic!("unexpected {e:?}"),
        }
    }
    assert_eq!(r.pqc_invocations, 1, "replays must not multiply PQC work");
    assert_eq!(replay_rejections, replays - 1);
    eprintln!(
        "[replay flood] submissions={replays} pqc_invocations=1 replay_rejections={replay_rejections}"
    );
}

#[test]
fn malformed_messages_never_panic_and_trigger_zero_pqc() {
    let mut r = Responder::new(GuardConfig::default(), 1_000);
    let lengths = [0usize, 1, 7, COOKIE_WIRE_LEN - 1, COOKIE_WIRE_LEN + 1, 4096];
    let mut malformed = 0u64;
    for &len in &lengths {
        for _ in 0..1_000 {
            let bytes = vec![0xA5u8; len];
            match Cookie::from_bytes(&bytes) {
                // Wrong length: rejected at parse (the daemon maps None -> Malformed).
                None => malformed += 1,
                // A correctly-sized but unsigned blob still fails the MAC check.
                Some(c) => r.attacker_admit(b"m", &c, 1_000),
            }
        }
    }
    assert_eq!(r.pqc_invocations, 0);
    assert!(malformed > 0);
    eprintln!(
        "[malformed   ] inputs={} malformed_rejected={malformed} pqc_invocations=0",
        lengths.len() * 1000
    );
}

#[test]
fn mixed_flood_resource_bounds_hold() {
    // A blended assault: legitimate clients, forged-cookie spam, and spoofed
    // sources, all in one window. Assert the gate's bounded state stays bounded
    // and the only PQC work done is for genuinely admitted connections.
    let cfg = GuardConfig {
        rate_capacity: 5,
        rate_refill_per_sec: 5,
        max_sources: 512,
        max_replay_entries: 1024,
        ..GuardConfig::default()
    };
    let mut r = Responder::new(cfg, 1_000);

    // 3 honest sources, each within budget.
    let mut honest_completed = 0u64;
    for s in 0..3u32 {
        let src = format!("honest-{s}");
        for _ in 0..5 {
            if r.honest_attempt(src.as_bytes(), 1_000).is_ok() {
                honest_completed += 1;
            }
        }
    }
    // 100k forged + spoofed nuisance messages.
    for i in 0..100_000u32 {
        let src = format!("spoof-{}", i % 4096);
        let forged = Cookie {
            issued_at: 1_000,
            server_nonce: [(i & 0xff) as u8; 16],
            mac: [(i >> 8) as u8; 32],
        };
        r.attacker_admit(src.as_bytes(), &forged, 1_000);
    }

    assert_eq!(
        r.pqc_invocations, honest_completed,
        "PQC ran only for genuinely admitted honest connections"
    );
    assert!(honest_completed >= 1);
    assert!(
        r.guard.tracked_sources() <= 512,
        "source map exceeded cap: {}",
        r.guard.tracked_sources()
    );
    assert!(
        r.guard.replay_entries() <= 1024,
        "replay set exceeded cap: {}",
        r.guard.replay_entries()
    );
    eprintln!(
        "[mixed flood ] honest_pqc={} tracked_sources={} replay_entries={} (caps 512/1024)",
        r.pqc_invocations,
        r.guard.tracked_sources(),
        r.guard.replay_entries()
    );
}
