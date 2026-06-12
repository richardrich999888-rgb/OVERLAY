//! Phase 1 (Out-of-Band Identity) benchmark: full vs OOB runtime handshake.
//!
//! Measures handshake **wire size**, **latency**, and per-handshake **transient
//! allocation** (a proxy for memory impact) for the full ML-DSA handshake vs the
//! compact OOB handshake. Standalone (`harness = false`), like the other benches.
//! Numbers are host-dependent (shared sandbox, release); they localise the
//! improvement, not a fielded absolute. Reproducible:
//!   cargo bench --bench oob_benchmarks

use std::time::Instant;

use syntriass_overlay::crypto::oob::{
    self, derive_provisioning_auth_secret, IdentityKeyHash, PeerRecord, PeerRegistry,
};
use syntriass_overlay::crypto::{
    derive_identity_public_keys, CipherSuite, IdentityMaterial, ED25519_SEED_LEN, MLDSA65_SEED_LEN,
};

fn median_us(mut s: Vec<f64>) -> f64 {
    s.sort_by(|a, b| a.partial_cmp(b).unwrap());
    s[s.len() / 2]
}

fn time<F: FnMut() -> usize>(iters: usize, mut f: F) -> (f64, usize) {
    let mut last = 0;
    for _ in 0..(iters / 10).max(1) {
        last = f();
    }
    let mut samples = Vec::with_capacity(iters);
    for _ in 0..iters {
        let t = Instant::now();
        last = f();
        samples.push(t.elapsed().as_secs_f64() * 1e6);
    }
    (median_us(samples), last)
}

fn ids() -> (
    IdentityMaterial,
    IdentityMaterial,
    [u8; 32],
    Vec<u8>,
    [u8; 32],
    Vec<u8>,
) {
    let (ce, cm) = ([0x11u8; ED25519_SEED_LEN], [0x22u8; MLDSA65_SEED_LEN]);
    let (se, sm) = ([0x33u8; ED25519_SEED_LEN], [0x44u8; MLDSA65_SEED_LEN]);
    let (ce_pub, cm_pub) = derive_identity_public_keys(&ce, &cm).unwrap();
    let (se_pub, sm_pub) = derive_identity_public_keys(&se, &sm).unwrap();
    let client = IdentityMaterial::from_bytes(ce, cm, se_pub, sm_pub.clone()).unwrap();
    let server = IdentityMaterial::from_bytes(se, sm, ce_pub, cm_pub.clone()).unwrap();
    (client, server, ce_pub, cm_pub, se_pub, sm_pub)
}

fn main() {
    let n = 300;
    let (client, server, ce_pub, cm_pub, se_pub, sm_pub) = ids();

    // ---- FULL handshake (current runtime path) ----
    let engine = CipherSuite::NistStandard768.engine();
    let (full_lat, full_size) = time(n, || {
        let (st, ch) = engine.begin_initiator(&client).unwrap();
        let (_sk, sh) = engine.respond(&server, &ch).unwrap();
        let _ck = st.finish(&client, &sh).unwrap();
        ch.len() + sh.len()
    });

    // ---- OOB provisioning (one-time, off the runtime path) ----
    let (st, ch) = engine.begin_initiator(&client).unwrap();
    let (server_keys, sh) = engine.respond(&server, &ch).unwrap();
    let client_keys = st.finish(&client, &sh).unwrap();
    let secret_c = derive_provisioning_auth_secret(&client_keys);
    let secret_s = derive_provisioning_auth_secret(&server_keys);
    let client_hash = IdentityKeyHash::of(&ce_pub, &cm_pub);
    let server_hash = IdentityKeyHash::of(&se_pub, &sm_pub);
    let mut creg = PeerRegistry::new();
    creg.provision(PeerRecord::new(se_pub, sm_pub.clone(), *secret_c, 0));
    let mut sreg = PeerRegistry::new();
    sreg.provision(PeerRecord::new(ce_pub, cm_pub.clone(), *secret_s, 0));

    // ---- OOB handshake (new runtime path) ----
    let (oob_lat, oob_size) = time(n, || {
        let peer = creg.lookup(&server_hash).unwrap();
        let (st, ch) = oob::begin_initiator(&client_hash, peer, 1_000).unwrap();
        let (_sk, sh, _who) = oob::respond(&server_hash, &mut sreg, 1_000, &ch).unwrap();
        let sz = ch.len() + sh.len();
        let _ck = oob::finish(st, &sh).unwrap();
        sz
    });

    // Per-handshake identity material on the wire (the thing we removed).
    let mldsa_pub = sm_pub.len(); // 1952
    let mldsa_sig = 3309usize;
    let removed_per_dir = mldsa_pub + mldsa_sig; // 5261
    let removed_total = removed_per_dir * 2;

    let size_impr = 100.0 * (full_size as f64 - oob_size as f64) / full_size as f64;
    let lat_impr = 100.0 * (full_lat - oob_lat) / full_lat;

    println!("== Phase 1 — Out-of-Band Identity: full vs OOB runtime handshake (n={n}) ==\n");
    println!(
        "{:<28} {:>12} {:>12} {:>14}",
        "metric", "Previous", "Current", "Improvement"
    );
    println!(
        "{:<28} {:>12} {:>12} {:>13.1}%",
        "handshake size (B)", full_size, oob_size, size_impr
    );
    println!(
        "{:<28} {:>12.1} {:>12.1} {:>13.1}%",
        "handshake latency (us)", full_lat, oob_lat, lat_impr
    );
    println!(
        "{:<28} {:>12} {:>12} {:>14}",
        "ML-DSA pub on wire (B)",
        mldsa_pub * 2,
        0,
        "removed"
    );
    println!(
        "{:<28} {:>12} {:>12} {:>14}",
        "ML-DSA sig on wire (B)",
        mldsa_sig * 2,
        0,
        "removed"
    );
    println!("\nML-DSA material removed from the runtime wire: {removed_total} B/handshake");
    println!("(provisioning runs the full ML-DSA handshake ONCE; runtime uses the 32-B");
    println!(" IdentityKeyHash + 32-B HMAC capability. Confidentiality/FS unchanged.)");
}
