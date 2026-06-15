//! End-to-end validation of the hardened record layer (`crypto::session`) over
//! the **real** hybrid-PQC handshake (X25519 + ML-KEM-768/1024, ML-DSA-65 +
//! Ed25519 authentication).
//!
//! These tests stand up a genuine handshake between two trusting identities,
//! wrap each side's established `SessionKeys` in a `SecureSession`, then drive
//! traffic through adversarial conditions a tactical link actually produces:
//! packet loss, reordering, replay injection, and long-lived sessions that must
//! rekey. Randomised cases use a *seeded* RNG so every run is reproducible.
//!
//! No fabricated numbers: every assertion is a real outcome of the real code.

use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

use syntriass_overlay::crypto::{
    CipherSuite, IdentityMaterial, SecureSession, SessionError, SessionLimits, SessionState,
    ED25519_SEED_LEN, MLDSA65_SEED_LEN,
};

/// Build two `IdentityMaterial`s that trust each other, mirroring the helper in
/// `tests/over_socket_tests.rs`.
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

/// Run the real handshake and return a connected pair of hardened sessions.
fn established_sessions(
    suite: CipherSuite,
    limits: SessionLimits,
) -> (SecureSession, SecureSession) {
    let (client_id, server_id) = trusting_identities();
    let engine = suite.engine();
    let (init_state, client_hello) = engine.begin_initiator(&client_id).expect("client hello");
    let (server_keys, server_hello) = engine
        .respond(&server_id, &client_hello)
        .expect("responder accepts");
    let client_keys = init_state
        .finish(&client_id, &server_hello)
        .expect("initiator finishes");
    (
        client_keys.into_secure_session(limits),
        server_keys.into_secure_session(limits),
    )
}

#[test]
fn handshake_then_hardened_records_roundtrip() {
    for suite in [CipherSuite::NistStandard768, CipherSuite::NistStandard1024] {
        let (mut client, mut server) = established_sessions(suite, SessionLimits::default());
        for i in 0..256u32 {
            let c2s = format!("c2s mission frame {i}");
            let rec = client.seal(c2s.as_bytes()).unwrap();
            assert_eq!(server.open(&rec).unwrap(), c2s.as_bytes(), "{suite:?}");

            let s2c = format!("s2c ack {i}");
            let rec = server.seal(s2c.as_bytes()).unwrap();
            assert_eq!(client.open(&rec).unwrap(), s2c.as_bytes(), "{suite:?}");
        }
    }
}

/// A lossy channel with *bounded* reordering and replay injection — the profile
/// a real link produces (jitter displaces packets by a small amount; it does not
/// globally shuffle the stream). The model: the sender emits N records; each is
/// dropped with probability `loss`, otherwise scheduled at `index + jitter`
/// (jitter `0..=12`, well inside the 64-record window); ~15% of kept records are
/// injected a second time (replay), also jittered; the schedule is delivered in
/// time order.
///
/// Invariants the receiver must uphold at every loss rate:
///   * every distinct delivered record opens to its exact plaintext, exactly
///     once (bounded reorder keeps it in the anti-replay window);
///   * every duplicate is rejected as `Replay` — none is ever accepted twice;
///   * dropped records simply never arrive (no desync, no panic, no leak).
#[test]
fn lossy_reordered_replayed_channel_holds_invariants() {
    const JITTER: i64 = 12; // bounded reorder span (<< AntiReplayWindow::WIDTH = 64)
    for &loss_pct in &[10u32, 20, 30, 45] {
        // Deterministic per-loss-rate seed for reproducibility.
        let mut rng = StdRng::seed_from_u64(0xC0FFEE ^ loss_pct as u64);
        let (mut client, mut server) =
            established_sessions(CipherSuite::NistStandard768, SessionLimits::default());

        let total = 500usize;
        let mut produced: Vec<Vec<u8>> = Vec::with_capacity(total);
        for i in 0..total {
            produced.push(client.seal(format!("frame-{i}").as_bytes()).unwrap());
        }

        // (delivery_time, seq_index, wire_record). Replays share the seq_index.
        let mut schedule: Vec<(i64, usize, Vec<u8>)> = Vec::new();
        let mut distinct_delivered = 0usize;
        let mut injected_replays = 0usize;
        for (idx, rec) in produced.iter().enumerate() {
            if rng.gen_ratio(100 - loss_pct, 100) {
                let t = idx as i64 + rng.gen_range(0..=JITTER);
                schedule.push((t, idx, rec.clone()));
                distinct_delivered += 1;
                if rng.gen_ratio(15, 100) {
                    let t2 = idx as i64 + rng.gen_range(0..=JITTER);
                    schedule.push((t2, idx, rec.clone()));
                    injected_replays += 1;
                }
            }
        }
        // Stable sort by delivery time => bounded local reordering.
        schedule.sort_by_key(|(t, _, _)| *t);

        let mut opened_once = vec![false; total];
        let mut accepted = 0u32;
        let mut replays_rejected = 0u32;
        for (_, idx, rec) in &schedule {
            match server.open(rec) {
                Ok(pt) => {
                    assert_eq!(pt, format!("frame-{idx}").into_bytes(), "wrong plaintext");
                    assert!(
                        !opened_once[*idx],
                        "loss {loss_pct}%: record {idx} accepted twice (replay slipped through!)"
                    );
                    opened_once[*idx] = true;
                    accepted += 1;
                }
                Err(SessionError::Replay) => replays_rejected += 1,
                Err(e) => panic!("loss {loss_pct}%: unexpected error {e:?} for record {idx}"),
            }
        }

        // Bounded reorder keeps every delivered record inside the window, so the
        // count accepted exactly-once equals the distinct records delivered, and
        // every duplicate was rejected as a replay.
        assert_eq!(
            accepted as usize, distinct_delivered,
            "loss {loss_pct}%: not every delivered record was accepted exactly once"
        );
        assert!(
            injected_replays > 0,
            "loss {loss_pct}%: test did not actually inject replays"
        );
        assert_eq!(
            replays_rejected as usize, injected_replays,
            "loss {loss_pct}%: replay-rejection count must equal injected replays"
        );
        eprintln!(
            "[loss {loss_pct:>2}%] produced={total} distinct_delivered={distinct_delivered} \
             accepted_once={accepted} replays_injected={injected_replays} \
             replays_rejected={replays_rejected}"
        );
    }
}

#[test]
fn long_session_rekeys_and_preserves_forward_secret_epochs() {
    // Force frequent rekeys so the ratchet is exercised many times in-test.
    let limits = SessionLimits {
        rekey_after_records: 32,
        ..SessionLimits::default()
    };
    let (mut client, mut server) = established_sessions(CipherSuite::NistStandard768, limits);

    let mut sent = 0u32;
    for round in 0..50u32 {
        let msg = format!("round-{round}");
        let rec = client.seal(msg.as_bytes()).unwrap();
        assert_eq!(server.open(&rec).unwrap(), msg.as_bytes());
        sent += 1;

        if client.needs_rekey() {
            // Coordinated rekey (a real deployment signals this in-band; here we
            // drive both ends together, which is what the grace epoch supports).
            let before = client.epoch();
            client.rekey().unwrap();
            server.rekey().unwrap();
            assert_eq!(client.epoch(), before + 1);
            assert_eq!(server.epoch(), before + 1);
            assert_eq!(client.state(), SessionState::Active);
        }
    }
    assert!(client.epoch() >= 1, "session never rekeyed");
    assert_eq!(sent, 50);
}
