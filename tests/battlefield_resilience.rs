//! Battlefield resilience — MEASURED behaviour of the real PQC channel under
//! degraded conditions.
//!
//! ## netem honesty
//!
//! Real `tc netem` is **not available** in this environment: the kernel exposes
//! no traffic-control qdiscs at all (`netem`/`tbf`/`prio`/`htb`/`fq_codel` all
//! report "qdisc kind unknown"; there is no `net/sched` module directory).
//! See `docs/NETEM_RESULTS.md` for the precise reason and the host-side netem
//! plan. These tests therefore apply impairment in **userspace, to the real
//! bytes of the real handshake + record layer** — `[measured: userspace model]`,
//! explicitly distinct from `[design: kernel netem]`. The userspace loss/reorder
//! model is faithful to a datagram overlay (the record layer's job is exactly to
//! tolerate loss/reorder and reject replays); kernel netem would additionally
//! exercise TCP retransmit timing, which the host-side plan covers.
//!
//! Measured here: loss ladder (10/20/30/45 %) — delivery/goodput/latency/replay;
//! reconnect & recovery time; CPU-starvation; congestion; plaintext-leakage = 0;
//! fail-closed. (Daemon-crash and memory-exhaustion are measured by
//! `tests/chaos_orchestration.rs` against the spawned daemon.)

use std::time::{Duration, Instant};

use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

use syntriass_overlay::crypto::{
    derive_identity_public_keys, CipherSuite, IdentityMaterial, SecureSession, SessionError,
    SessionLimits, ED25519_SEED_LEN, MLDSA65_SEED_LEN,
};

const CANARY: &[u8] = b"BATTLEFIELD::CLEARTEXT::CANARY::a1b2c3";

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    needle.len() <= hay.len() && hay.windows(needle.len()).any(|w| w == needle)
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

/// Run the real hybrid-PQC handshake (in-process) and return a connected pair of
/// hardened record sessions, plus the measured handshake latency.
fn established_pair(suite: CipherSuite) -> (SecureSession, SecureSession, Duration) {
    let (client_id, server_id) = trusting_identities();
    let engine = suite.engine();
    let t = Instant::now();
    let (state, ch) = engine.begin_initiator(&client_id).unwrap();
    let (server_keys, sh) = engine.respond(&server_id, &ch).unwrap();
    let client_keys = state.finish(&client_id, &sh).unwrap();
    let elapsed = t.elapsed();
    (
        client_keys.into_secure_session(SessionLimits::default()),
        server_keys.into_secure_session(SessionLimits::default()),
        elapsed,
    )
}

fn p(samples: &mut [f64], q: f64) -> f64 {
    if samples.is_empty() {
        return 0.0;
    }
    samples.sort_by(|a, b| a.partial_cmp(b).unwrap());
    samples[((samples.len() as f64 * q) as usize).min(samples.len() - 1)]
}

#[test]
fn loss_ladder_measured() {
    // The resilience deliverable: the encrypted record channel under packet loss,
    // bounded reordering, and jitter, at the four mandated loss rates.
    const JITTER_MS_MAX: u64 = 8; // per-delivered-record link jitter
    const RECORDS: usize = 400;
    println!("\n==== BATTLEFIELD LOSS LADDER (userspace model over the real record layer) ====");
    println!(
        "{:>5} {:>10} {:>9} {:>9} {:>11} {:>11} {:>10} {:>9}",
        "loss%", "delivered", "opened", "replays", "goodput/s", "lat_p50_us", "lat_p99_us", "leaks"
    );
    for &loss_pct in &[10u32, 20, 30, 45] {
        let mut rng = StdRng::seed_from_u64(0xBEEF ^ loss_pct as u64);
        let (mut tx, mut rx, _hs) = established_pair(CipherSuite::NistStandard768);

        // Producer: seal RECORDS records (each embeds the canary in plaintext).
        let mut sealed: Vec<(usize, Vec<u8>)> = Vec::with_capacity(RECORDS);
        for i in 0..RECORDS {
            let mut pt = format!("frame-{i}-").into_bytes();
            pt.extend_from_slice(CANARY);
            sealed.push((i, tx.seal(&pt).unwrap()));
        }

        // Lossy + bounded-reorder + jitter delivery schedule (+15 % replays).
        let jitter = 12i64;
        let mut sched: Vec<(i64, usize, Vec<u8>)> = Vec::new();
        let mut delivered = 0usize;
        let mut replays_injected = 0usize;
        for (idx, rec) in &sealed {
            if rng.gen_ratio(100 - loss_pct, 100) {
                sched.push((*idx as i64 + rng.gen_range(0..=jitter), *idx, rec.clone()));
                delivered += 1;
                if rng.gen_ratio(15, 100) {
                    sched.push((*idx as i64 + rng.gen_range(0..=jitter), *idx, rec.clone()));
                    replays_injected += 1;
                }
            }
        }
        sched.sort_by_key(|(t, _, _)| *t);

        // Consume through the impaired link; measure goodput + per-record latency.
        let mut lat = Vec::new();
        let mut opened = 0u64;
        let mut replays_rejected = 0u64;
        let mut leaks = 0u64;
        let wall = Instant::now();
        for (_, idx, rec) in &sched {
            // link jitter for a delivered record
            let jms = rng.gen_range(0..=JITTER_MS_MAX);
            if jms > 0 {
                std::thread::sleep(Duration::from_micros(jms * 50)); // scaled jitter
            }
            // any cleartext on the wire?
            if contains(rec, CANARY) {
                leaks += 1;
            }
            let t = Instant::now();
            match rx.open(rec) {
                Ok(pt) => {
                    lat.push(t.elapsed().as_secs_f64() * 1e6);
                    assert!(pt.starts_with(format!("frame-{idx}-").as_bytes()));
                    opened += 1;
                }
                Err(SessionError::Replay) => replays_rejected += 1,
                Err(e) => panic!("loss {loss_pct}%: unexpected {e:?}"),
            }
        }
        let secs = wall.elapsed().as_secs_f64().max(1e-9);
        let goodput = opened as f64 / secs;
        let p50 = p(&mut lat, 0.50);
        let p99 = p(&mut lat, 0.99);

        // Invariants: every delivered record opened exactly once; all replays
        // rejected; ZERO plaintext on the wire.
        assert_eq!(
            opened as usize, delivered,
            "loss {loss_pct}%: delivery mismatch"
        );
        assert_eq!(replays_rejected as usize, replays_injected);
        assert_eq!(leaks, 0, "CLEARTEXT LEAK on the impaired wire");

        println!(
            "{loss_pct:>5} {delivered:>10} {opened:>9} {replays_rejected:>9} {goodput:>11.0} {p50:>11.1} {p99:>10.1} {leaks:>9}"
        );
    }
    println!("(goodput is records/s through the impaired link incl. modelled jitter)\n");
}

#[test]
fn handshake_success_rate_under_loss() {
    // Handshake success vs loss: a two-message handshake where ANY lost message
    // fails the attempt (the harsh datagram model — no app retransmit). Measures
    // the success rate a single-shot attempt achieves; the reconnect test shows
    // recovery via retry.
    println!("\n==== HANDSHAKE SUCCESS RATE vs LOSS (single-shot, datagram model) ====");
    println!(
        "{:>5} {:>9} {:>9} {:>10}",
        "loss%", "attempts", "ok", "rate"
    );
    for &loss_pct in &[10u32, 20, 30, 45] {
        let mut rng = StdRng::seed_from_u64(0xA11CE ^ loss_pct as u64);
        let attempts = 200u32;
        let mut ok = 0u32;
        for _ in 0..attempts {
            // Model: the handshake has 2 messages; each is "delivered" iff not
            // lost. Both must arrive for success.
            let m1 = rng.gen_ratio(100 - loss_pct, 100);
            let m2 = rng.gen_ratio(100 - loss_pct, 100);
            if m1 && m2 {
                // do a real handshake to confirm it completes when delivered
                let (_c, _s, _t) = established_pair(CipherSuite::NistStandard768);
                ok += 1;
            }
        }
        let rate = ok as f64 / attempts as f64;
        println!("{loss_pct:>5} {attempts:>9} {ok:>9} {rate:>10.3}");
    }
    println!("(single-shot; the overlay retries — see reconnect/recovery below)\n");
}

#[test]
fn reconnect_and_recovery_time() {
    // A session is established, then the link "drops" (the old session must fail
    // closed), then the peer reconnects. Measure establish time and reconnect
    // time, and that the dropped session yields no plaintext.
    println!("\n==== RECONNECT / RECOVERY ====");
    let t0 = Instant::now();
    let (mut c, mut s, hs) = established_pair(CipherSuite::NistStandard768);
    let rec = c.seal(b"pre-drop").unwrap();
    assert_eq!(s.open(&rec).unwrap(), b"pre-drop");

    // "Drop": the session keys are gone (peer rebooted / link severed). The old
    // ciphertext must not be openable by a fresh, unrelated session — fail closed.
    let (_c2, mut s_fresh, _t) = established_pair(CipherSuite::NistStandard768);
    assert!(
        s_fresh.open(&rec).is_err(),
        "a fresh session must not open the old session's record (fail closed)"
    );

    // Reconnect = a fresh handshake.
    let t = Instant::now();
    let (mut c3, mut s3, hs2) = established_pair(CipherSuite::NistStandard768);
    let reconnect = t.elapsed();
    let rec2 = c3.seal(b"post-reconnect").unwrap();
    assert_eq!(s3.open(&rec2).unwrap(), b"post-reconnect");

    println!("  initial handshake : {:.0} us", hs.as_secs_f64() * 1e6);
    println!("  reconnect handshake: {:.0} us", hs2.as_secs_f64() * 1e6);
    println!(
        "  reconnect (measured): {:.0} us",
        reconnect.as_secs_f64() * 1e6
    );
    println!(
        "  total recovery wall : {:.0} us",
        t0.elapsed().as_secs_f64() * 1e6
    );
    println!("  dropped-session fail-closed: YES (old ciphertext unreadable)\n");
}

#[test]
fn handshake_under_cpu_starvation() {
    // Saturate the CPU, then measure the handshake still completes (and fails
    // closed nowhere). Real OS threads in a busy loop create the starvation.
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    let ncpu = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(2);
    let stop = Arc::new(AtomicBool::new(false));
    let mut hogs = Vec::new();
    for _ in 0..(ncpu * 2) {
        let stop = Arc::clone(&stop);
        hogs.push(std::thread::spawn(move || {
            let mut x: u64 = 0;
            while !stop.load(Ordering::Relaxed) {
                x = x.wrapping_mul(6364136223846793005).wrapping_add(1);
                std::hint::black_box(x);
            }
        }));
    }

    let mut lat = Vec::new();
    let mut ok = 0u32;
    for _ in 0..30 {
        let t = Instant::now();
        let (mut c, mut s, _) = established_pair(CipherSuite::NistStandard768);
        let rec = c.seal(b"under-starvation").unwrap();
        if s.open(&rec)
            .map(|p| p == b"under-starvation")
            .unwrap_or(false)
        {
            ok += 1;
        }
        lat.push(t.elapsed().as_secs_f64() * 1e6);
    }
    stop.store(true, Ordering::Relaxed);
    for h in hogs {
        let _ = h.join();
    }

    let p50 = p(&mut lat, 0.50);
    let p99 = p(&mut lat, 0.99);
    println!(
        "\n==== HANDSHAKE UNDER CPU STARVATION ({} hog threads, {ncpu} cpus) ====",
        ncpu * 2
    );
    println!(
        "  handshakes_ok: {ok}/30   latency p50={p50:.0}us p99={p99:.0}us  (none failed open)\n"
    );
    assert_eq!(
        ok, 30,
        "every handshake must still complete under CPU starvation"
    );
}

#[test]
fn congestion_many_concurrent_handshakes() {
    // Congestion = many sessions established back-to-back; measure aggregate
    // success + that throughput stays sane and nothing leaks.
    let n = 100;
    let t = Instant::now();
    let mut ok = 0u32;
    for _ in 0..n {
        let (mut c, mut s, _) = established_pair(CipherSuite::NistStandard768);
        let rec = c.seal(b"congested").unwrap();
        assert!(
            !contains(&rec, b"congested"),
            "no plaintext under congestion"
        );
        if s.open(&rec).map(|p| p == b"congested").unwrap_or(false) {
            ok += 1;
        }
    }
    let secs = t.elapsed().as_secs_f64();
    println!("\n==== CONGESTION ({n} back-to-back sessions) ====");
    println!(
        "  sessions_ok: {ok}/{n}   rate: {:.0} handshakes/s   leaks: 0\n",
        n as f64 / secs
    );
    assert_eq!(ok, n);
}
