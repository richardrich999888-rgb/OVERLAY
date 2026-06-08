//! In-process, reproducible micro-benchmarks for the asymmetric control plane.
//!
//! These measure the *crypto* cost in isolation (no sockets, no Python), which
//! is the honest lower bound for the handshake-latency and handshake-size
//! targets. End-to-end numbers (with TCP + the app) come from
//! `tests/characterize.py` and are strictly larger.
//!
//! Run:
//!   cargo test --release --lib crypto::bench -- --nocapture --test-threads=1
#![cfg(test)]

use super::{CipherSuite, IdentityMaterial, ED25519_SEED_LEN, MLDSA65_SEED_LEN};
use ed25519_dalek::SigningKey as Ed25519SigningKey;
use ml_dsa::{Keypair, MlDsa65, SigningKey as MlDsaSigningKey};
use std::time::Instant;

const HANDSHAKE_FRAME_OVERHEAD: usize = 4 + 1 + 1; // u32 len + suite_id + type

struct RawIdentities {
    client_ed_seed: [u8; ED25519_SEED_LEN],
    client_ml_seed: [u8; MLDSA65_SEED_LEN],
    server_ed_seed: [u8; ED25519_SEED_LEN],
    server_ml_seed: [u8; MLDSA65_SEED_LEN],
    client_ed_pub: [u8; 32],
    client_ml_pub: Vec<u8>,
    server_ed_pub: [u8; 32],
    server_ml_pub: Vec<u8>,
}

fn raw_identities() -> RawIdentities {
    let client_ed_seed = [0x11u8; ED25519_SEED_LEN];
    let client_ml_seed = [0x22u8; MLDSA65_SEED_LEN];
    let server_ed_seed = [0x33u8; ED25519_SEED_LEN];
    let server_ml_seed = [0x44u8; MLDSA65_SEED_LEN];

    let client_ed_pub = Ed25519SigningKey::from_bytes(&client_ed_seed)
        .verifying_key()
        .to_bytes();
    let client_ml_arr = ml_dsa::Seed::try_from(&client_ml_seed[..]).unwrap();
    let client_ml_pub = MlDsaSigningKey::<MlDsa65>::from_seed(&client_ml_arr)
        .verifying_key()
        .encode()
        .as_slice()
        .to_vec();
    let server_ed_pub = Ed25519SigningKey::from_bytes(&server_ed_seed)
        .verifying_key()
        .to_bytes();
    let server_ml_arr = ml_dsa::Seed::try_from(&server_ml_seed[..]).unwrap();
    let server_ml_pub = MlDsaSigningKey::<MlDsa65>::from_seed(&server_ml_arr)
        .verifying_key()
        .encode()
        .as_slice()
        .to_vec();

    RawIdentities {
        client_ed_seed,
        client_ml_seed,
        server_ed_seed,
        server_ml_seed,
        client_ed_pub,
        client_ml_pub,
        server_ed_pub,
        server_ml_pub,
    }
}

fn client_identity(r: &RawIdentities) -> IdentityMaterial {
    IdentityMaterial::from_bytes(
        r.client_ed_seed,
        r.client_ml_seed,
        r.server_ed_pub,
        r.server_ml_pub.clone(),
    )
    .unwrap()
}

fn server_identity(r: &RawIdentities) -> IdentityMaterial {
    IdentityMaterial::from_bytes(
        r.server_ed_seed,
        r.server_ml_seed,
        r.client_ed_pub,
        r.client_ml_pub.clone(),
    )
    .unwrap()
}

/// One full handshake (initiator begin -> responder respond -> initiator finish)
/// using pre-built identity material. Returns nothing; we only time it.
fn run_handshake(suite: CipherSuite, client: &IdentityMaterial, server: &IdentityMaterial) {
    let engine = suite.engine();
    let (state, client_hello) = engine.begin_initiator(client).expect("client hello");
    let (_skeys, server_hello) = engine.respond(server, &client_hello).expect("respond");
    let _ckeys = state.finish(client, &server_hello).expect("finish");
}

fn percentile(sorted_ms: &[f64], p: f64) -> f64 {
    if sorted_ms.is_empty() {
        return f64::NAN;
    }
    let rank = (p / 100.0) * (sorted_ms.len() as f64 - 1.0);
    let lo = rank.floor() as usize;
    let hi = rank.ceil() as usize;
    if lo == hi {
        sorted_ms[lo]
    } else {
        let frac = rank - lo as f64;
        sorted_ms[lo] * (1.0 - frac) + sorted_ms[hi] * frac
    }
}

fn summarize(label: &str, mut samples_ms: Vec<f64>) {
    samples_ms.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let n = samples_ms.len();
    let mean = samples_ms.iter().sum::<f64>() / n as f64;
    println!(
        "  {label:<34} n={n}  mean={mean:.3}  p50={:.3}  p90={:.3}  p99={:.3}  max={:.3}  (ms)",
        percentile(&samples_ms, 50.0),
        percentile(&samples_ms, 90.0),
        percentile(&samples_ms, 99.0),
        percentile(&samples_ms, 100.0),
    );
}

#[test]
#[ignore = "benchmark; run with `cargo test --release -- --ignored` or by name"]
fn bench_handshake_latency() {
    let r = raw_identities();
    let warmup = 30;
    let iters = 500;

    println!("\n== Asymmetric handshake latency (in-process, no sockets) ==");
    println!("   target: P99 <= 1.5 ms");
    for suite in [CipherSuite::NistStandard768, CipherSuite::NistStandard1024] {
        let client = client_identity(&r);
        let server = server_identity(&r);

        // (a) identity material pre-built (best case: caching done right)
        for _ in 0..warmup {
            run_handshake(suite, &client, &server);
        }
        let mut a = Vec::with_capacity(iters);
        for _ in 0..iters {
            let t = Instant::now();
            run_handshake(suite, &client, &server);
            a.push(t.elapsed().as_secs_f64() * 1e3);
        }
        summarize(&format!("{suite:?} [identity cached]"), a);

        // (b) rebuild IdentityMaterial each handshake (what resolve_identity()
        // does today, minus the file read) -- quantifies caching headroom.
        for _ in 0..warmup {
            let c = client_identity(&r);
            let s = server_identity(&r);
            run_handshake(suite, &c, &s);
        }
        let mut b = Vec::with_capacity(iters);
        for _ in 0..iters {
            let t = Instant::now();
            let c = client_identity(&r);
            let s = server_identity(&r);
            run_handshake(suite, &c, &s);
            b.push(t.elapsed().as_secs_f64() * 1e3);
        }
        summarize(&format!("{suite:?} [identity rebuilt]"), b);
    }
}

#[test]
#[ignore = "benchmark; run with `cargo test --release -- --ignored` or by name"]
fn bench_handshake_size() {
    let r = raw_identities();
    println!("\n== Handshake wire size ==");
    println!("   target: total overhead <= 2 KB (2048 bytes)");
    for suite in [CipherSuite::NistStandard768, CipherSuite::NistStandard1024] {
        let client = client_identity(&r);
        let server = server_identity(&r);
        let engine = suite.engine();
        let (state, client_hello) = engine.begin_initiator(&client).unwrap();
        let (_k, server_hello) = engine.respond(&server, &client_hello).unwrap();
        let _ = state.finish(&client, &server_hello).unwrap();

        let ch = client_hello.len() + HANDSHAKE_FRAME_OVERHEAD;
        let sh = server_hello.len() + HANDSHAKE_FRAME_OVERHEAD;
        let total = ch + sh;
        let name = format!("{suite:?}");
        println!(
            "  {name:<22} ClientHello={ch} B  ServerHello={sh} B  total={total} B  ({:.1} KB)  -> {}",
            total as f64 / 1024.0,
            if total <= 2048 { "PASS" } else { "MISS" }
        );
    }
}

#[test]
#[ignore = "benchmark; run with `cargo test --release -- --ignored` or by name"]
fn bench_aead_throughput() {
    use super::SessionKeys;
    // Build one established session via a real handshake, then stream records.
    let r = raw_identities();
    let client = client_identity(&r);
    let server = server_identity(&r);
    let engine = CipherSuite::NistStandard768.engine();
    let (state, client_hello) = engine.begin_initiator(&client).unwrap();
    let (mut skeys, server_hello) = engine.respond(&server, &client_hello).unwrap();
    let mut ckeys: SessionKeys = state.finish(&client, &server_hello).unwrap();

    let record = vec![0xA5u8; 16 * 1024]; // 16 KiB records (overlay MAX is 64 KiB)
    let records = 4096;
    println!("\n== Symmetric record path (AES-256-GCM seal+open, in-process) ==");

    let t = Instant::now();
    let mut bytes = 0u64;
    for _ in 0..records {
        let ct = ckeys.seal(&record).unwrap();
        let pt = skeys.open(&ct).unwrap();
        debug_assert_eq!(pt.len(), record.len());
        bytes += record.len() as u64;
    }
    let secs = t.elapsed().as_secs_f64();
    let mbps = (bytes as f64 / (1024.0 * 1024.0)) / secs;
    println!(
        "  seal+open throughput: {mbps:.0} MB/s over {} MiB ({} records x 16 KiB)",
        bytes / (1024 * 1024),
        records
    );
    println!("  note: this is the AEAD ceiling; the v1 userspace socket path is");
    println!("        bottlenecked by buffer copies, not the cipher (see characterize.py).");
}
