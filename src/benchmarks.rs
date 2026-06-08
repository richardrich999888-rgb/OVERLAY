//! Automated, reproducible benchmark harness for the live defense demo.
//!
//! Real loops only — no synthetic numbers. Run with `cargo bench` (wired through
//! `benches/demo_benchmarks.rs`). Measures:
//!   1. Handshake latency P50/P99: in-band (ML-DSA + ML-KEM) vs an out-of-band
//!      ML-KEM-only *projection* (unauthenticated; quantifies the signature tax).
//!   2. Handshake envelope size: in-band (~13 KB) vs ML-KEM-only (< 2 KB).
//!   3. Real localhost socket throughput (plaintext baseline) + AEAD ceiling.
//!
//! The in-process crypto numbers are a lower bound; end-to-end socket numbers
//! (with the LD_PRELOAD overlay) come from `tests/characterize.py`.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::Instant;

use ed25519_dalek::SigningKey as Ed25519SigningKey;
use ml_dsa::{Keypair, MlDsa65, SigningKey as MlDsaSigningKey};
use ml_kem::kem::{Decapsulate, Encapsulate};
use ml_kem::{EncodedSizeUser, KemCore, MlKem1024, MlKem768};
use x25519_dalek::{EphemeralSecret, PublicKey as XPublicKey};

use crate::crypto::{
    CipherSuite, IdentityMaterial, ED25519_SEED_LEN, MLDSA65_SEED_LEN, X25519_LEN,
};

const FRAME_OVERHEAD: usize = 4 + 1 + 1; // u32 len + suite_id + type

/// Entry point invoked by `benches/demo_benchmarks.rs`.
pub fn run_all() {
    println!("================ SYNTRIASS demo benchmarks (real loops) ================");
    handshake_latency();
    kem_only_projection();
    handshake_size();
    socket_throughput();
    println!("=======================================================================");
}

// --------------------------- identity construction ---------------------------

struct Ids {
    client: IdentityMaterial,
    server: IdentityMaterial,
}

fn build_identities() -> Ids {
    let client_ed = [0x11u8; ED25519_SEED_LEN];
    let client_ml = [0x22u8; MLDSA65_SEED_LEN];
    let server_ed = [0x33u8; ED25519_SEED_LEN];
    let server_ml = [0x44u8; MLDSA65_SEED_LEN];

    let client_ed_pub = Ed25519SigningKey::from_bytes(&client_ed)
        .verifying_key()
        .to_bytes();
    let client_ml_pub =
        MlDsaSigningKey::<MlDsa65>::from_seed(&ml_dsa::Seed::try_from(&client_ml[..]).unwrap())
            .verifying_key()
            .encode()
            .as_slice()
            .to_vec();
    let server_ed_pub = Ed25519SigningKey::from_bytes(&server_ed)
        .verifying_key()
        .to_bytes();
    let server_ml_pub =
        MlDsaSigningKey::<MlDsa65>::from_seed(&ml_dsa::Seed::try_from(&server_ml[..]).unwrap())
            .verifying_key()
            .encode()
            .as_slice()
            .to_vec();

    Ids {
        client: IdentityMaterial::from_bytes(client_ed, client_ml, server_ed_pub, server_ml_pub)
            .unwrap(),
        server: IdentityMaterial::from_bytes(server_ed, server_ml, client_ed_pub, client_ml_pub)
            .unwrap(),
    }
}

// ------------------------------- percentiles ---------------------------------

fn percentile(sorted: &[f64], p: f64) -> f64 {
    if sorted.is_empty() {
        return f64::NAN;
    }
    let rank = (p / 100.0) * (sorted.len() as f64 - 1.0);
    let lo = rank.floor() as usize;
    let hi = rank.ceil() as usize;
    if lo == hi {
        sorted[lo]
    } else {
        sorted[lo] * (1.0 - (rank - lo as f64)) + sorted[hi] * (rank - lo as f64)
    }
}

fn report(label: &str, mut ms: Vec<f64>) {
    ms.sort_by(|a, b| a.partial_cmp(b).unwrap());
    println!(
        "  {label:<40} p50={:.3} ms  p99={:.3} ms  max={:.3} ms  (n={})",
        percentile(&ms, 50.0),
        percentile(&ms, 99.0),
        percentile(&ms, 100.0),
        ms.len()
    );
}

// --------------------------- 1. handshake latency ----------------------------

fn handshake_latency() {
    println!(
        "\n[1] In-band handshake latency (ML-DSA + ML-KEM, identity cached)  target P99 <= 1.5 ms"
    );
    let ids = build_identities();
    for suite in [CipherSuite::NistStandard768, CipherSuite::NistStandard1024] {
        let engine = suite.engine();
        for _ in 0..30 {
            run_inband(&*engine, &ids);
        }
        let mut samples = Vec::with_capacity(300);
        for _ in 0..300 {
            let t = Instant::now();
            run_inband(&*engine, &ids);
            samples.push(t.elapsed().as_secs_f64() * 1e3);
        }
        report(&format!("{suite:?}"), samples);
    }
}

fn run_inband(engine: &dyn crate::crypto::SovereignCryptoEngine, ids: &Ids) {
    let (state, ch) = engine.begin_initiator(&ids.client).unwrap();
    let (_sk, sh) = engine.respond(&ids.server, &ch).unwrap();
    let _ck = state.finish(&ids.client, &sh).unwrap();
}

// ------------------- 2a. ML-KEM-only projection (latency) --------------------

fn kem_only_projection() {
    println!("\n[2] ML-KEM-only projection (X25519 + ML-KEM, NO signatures)");
    println!("    NOTE: unauthenticated — removing in-band signatures removes peer");
    println!("    authentication (MITM-exposed). Shown only to quantify the PQ-signature tax.");
    kem_only_one::<MlKem768>("NistStandard768 (KEM-only)");
    kem_only_one::<MlKem1024>("NistStandard1024 (KEM-only)");
}

fn kem_only_one<K: KemCore>(label: &str) {
    for _ in 0..30 {
        let _ = kem_exchange::<K>();
    }
    let mut samples = Vec::with_capacity(300);
    let mut wire = 0usize;
    for _ in 0..300 {
        let t = Instant::now();
        wire = kem_exchange::<K>();
        samples.push(t.elapsed().as_secs_f64() * 1e3);
    }
    report(label, samples);
    let total = wire + 2 * FRAME_OVERHEAD;
    println!(
        "       envelope: {total} B ({:.1} KB)  -> {}",
        total as f64 / 1024.0,
        if total <= 2048 { "PASS <=2KB" } else { "MISS" }
    );
}

/// One full hybrid X25519 + ML-KEM exchange without signatures. Returns the
/// ClientHello+ServerHello wire size (key material only).
fn kem_exchange<K: KemCore>() -> usize {
    let mut rng = rand_core::OsRng;

    // Initiator: X25519 ephemeral + ML-KEM keypair.
    let i_x = EphemeralSecret::random();
    let i_xpub = XPublicKey::from(&i_x);
    let (decap, encap) = K::generate(&mut rng);
    let ek = encap.as_bytes();

    // Responder: X25519 ephemeral + encapsulate to the initiator's ek.
    let r_x = EphemeralSecret::random();
    let r_xpub = XPublicKey::from(&r_x);
    let (ct, _ss_r) = encap.encapsulate(&mut rng).unwrap();
    let _r_shared = r_x.diffie_hellman(&i_xpub);

    // Initiator finishes: decapsulate + DH.
    let _ss_i = decap.decapsulate(&ct).unwrap();
    let _i_shared = i_x.diffie_hellman(&r_xpub);

    // ClientHello = xpub || ek ; ServerHello = xpub || ct
    let ch = X25519_LEN + ek.as_slice().len();
    let sh = X25519_LEN + ct.as_slice().len();
    ch + sh
}

// --------------------------- 2b. in-band size --------------------------------

fn handshake_size() {
    println!("\n[3] In-band handshake envelope size  target <= 2 KB");
    let ids = build_identities();
    for suite in [CipherSuite::NistStandard768, CipherSuite::NistStandard1024] {
        let engine = suite.engine();
        let (state, ch) = engine.begin_initiator(&ids.client).unwrap();
        let (_sk, sh) = engine.respond(&ids.server, &ch).unwrap();
        let _ = state.finish(&ids.client, &sh).unwrap();
        let total = ch.len() + sh.len() + 2 * FRAME_OVERHEAD;
        println!(
            "  {:<22} ClientHello={} B  ServerHello={} B  total={total} B ({:.1} KB)  -> {}",
            format!("{suite:?}"),
            ch.len() + FRAME_OVERHEAD,
            sh.len() + FRAME_OVERHEAD,
            total as f64 / 1024.0,
            if total <= 2048 { "PASS" } else { "MISS" }
        );
    }
}

// ----------------------- 3. real socket throughput ---------------------------

fn socket_throughput() {
    println!("\n[4] Throughput");
    let total = 256 * 1024 * 1024usize; // 256 MiB
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    let server = thread::spawn(move || {
        let (mut s, _) = listener.accept().unwrap();
        let mut buf = vec![0u8; 256 * 1024];
        let mut got = 0usize;
        loop {
            match s.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => got += n,
                Err(_) => break,
            }
        }
        got
    });

    let mut c = TcpStream::connect(addr).unwrap();
    c.set_nodelay(true).ok();
    let chunk = vec![0xABu8; 256 * 1024];
    let t = Instant::now();
    let mut sent = 0usize;
    while sent < total {
        c.write_all(&chunk).unwrap();
        sent += chunk.len();
    }
    drop(c);
    let got = server.join().unwrap();
    let secs = t.elapsed().as_secs_f64();
    println!(
        "  plaintext loopback TCP : {:.0} MB/s ({} MiB) -- the v1 line-rate baseline",
        (got as f64 / 1_048_576.0) / secs,
        got / 1_048_576
    );

    // AEAD ceiling: the cipher is not the bottleneck; userspace copies are.
    aead_ceiling();
    println!(
        "  end-to-end overlay socket throughput: see tests/characterize.py (real LD_PRELOAD path)"
    );
}

fn aead_ceiling() {
    let ids = build_identities();
    let engine = CipherSuite::NistStandard768.engine();
    let (state, ch) = engine.begin_initiator(&ids.client).unwrap();
    let (mut sk, sh) = engine.respond(&ids.server, &ch).unwrap();
    let mut ck = state.finish(&ids.client, &sh).unwrap();

    let record = vec![0xA5u8; 16 * 1024];
    let records = 8192;
    let t = Instant::now();
    let mut bytes = 0u64;
    for _ in 0..records {
        let ct = ck.seal(&record).unwrap();
        let _ = sk.open(&ct).unwrap();
        bytes += record.len() as u64;
    }
    let secs = t.elapsed().as_secs_f64();
    println!(
        "  AES-256-GCM seal+open  : {:.0} MB/s ({} MiB) -- cipher ceiling, not the bottleneck",
        (bytes as f64 / 1_048_576.0) / secs,
        bytes / 1_048_576
    );
}
