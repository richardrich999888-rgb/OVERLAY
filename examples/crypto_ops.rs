//! Isolated crypto micro-benchmark: decompose the wire handshake latency (Gate 4)
//! into named per-operation costs.
//!
//! Measurement only. Does not touch src/. Uses the exact pinned crate versions
//! (ed25519-dalek 2.2.0, ml-dsa 0.1.1, ml-kem 0.2.3, x25519-dalek 2.0.1) via the
//! same idioms the production code in src/crypto uses, plus the crate's own
//! public handshake API (begin_initiator / respond / finish) so the composite
//! number is the real code path, not a re-implementation.
//!
//! No criterion: plain std::time::Instant + std::hint::black_box, so there is no
//! new dependency and no Cargo.toml change (examples/ is auto-discovered).
//!
//!   cargo run --release --example crypto_ops

use std::hint::black_box;
use std::time::Instant;

use ed25519_dalek::{Signer as EdSigner, SigningKey as EdSigningKey};
use ml_dsa::{
    Keypair as MlKeypair, MlDsa65, Seed as MlDsaSeed, Signer as MlSigner,
    SigningKey as MlDsaSigningKey, Verifier as MlVerifier,
};
use ml_kem::kem::{Decapsulate, Encapsulate};
use ml_kem::{KemCore, MlKem1024, MlKem768};
use rand_core::OsRng;
use x25519_dalek::{EphemeralSecret, PublicKey as XPublicKey};

use syntriass_overlay::crypto::{CipherSuite, IdentityMaterial, ED25519_SEED_LEN, MLDSA65_SEED_LEN};

const FAST_ITERS: usize = 5000; // X25519, Ed25519, AES-GCM
const SLOW_ITERS: usize = 1000; // ML-KEM, ML-DSA, composite handshake
const WARMUP: usize = 50;
const AUTH_MSG_LEN: usize = 4096; // representative signed-transcript size

struct Stat {
    median: f64,
    p95: f64,
    max: f64,
}

fn bench<F: FnMut()>(iters: usize, mut f: F) -> Stat {
    for _ in 0..WARMUP {
        f();
    }
    let mut s = Vec::with_capacity(iters);
    for _ in 0..iters {
        let t = Instant::now();
        f();
        s.push(t.elapsed().as_secs_f64() * 1000.0);
    }
    s.sort_by(|a, b| a.partial_cmp(b).unwrap());
    Stat {
        median: s[iters / 2],
        p95: s[((iters as f64) * 0.95) as usize],
        max: *s.last().unwrap(),
    }
}

fn row(name: &str, n: usize, st: &Stat) {
    println!(
        "{:<26} {:>8} {:>12.4} {:>12.4} {:>12.4}",
        name, n, st.median, st.p95, st.max
    );
}

// Build a (client, server) identity pair exactly as the production tests do.
fn identities() -> (IdentityMaterial, IdentityMaterial) {
    let client_ed = [0x11u8; ED25519_SEED_LEN];
    let client_ml = [0x22u8; MLDSA65_SEED_LEN];
    let server_ed = [0x33u8; ED25519_SEED_LEN];
    let server_ml = [0x44u8; MLDSA65_SEED_LEN];

    let c_ed_pub = EdSigningKey::from_bytes(&client_ed).verifying_key().to_bytes();
    let s_ed_pub = EdSigningKey::from_bytes(&server_ed).verifying_key().to_bytes();
    let c_ml_seed = MlDsaSeed::try_from(&client_ml[..]).unwrap();
    let s_ml_seed = MlDsaSeed::try_from(&server_ml[..]).unwrap();
    let c_ml_pub = MlDsaSigningKey::<MlDsa65>::from_seed(&c_ml_seed)
        .verifying_key()
        .encode()
        .as_slice()
        .to_vec();
    let s_ml_pub = MlDsaSigningKey::<MlDsa65>::from_seed(&s_ml_seed)
        .verifying_key()
        .encode()
        .as_slice()
        .to_vec();

    let client = IdentityMaterial::from_bytes(client_ed, client_ml, s_ed_pub, s_ml_pub).unwrap();
    let server = IdentityMaterial::from_bytes(server_ed, server_ml, c_ed_pub, c_ml_pub).unwrap();
    (client, server)
}

fn main() {
    let cores = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(0);
    println!("crypto_ops micro-benchmark");
    println!(
        "iters: fast(X25519/Ed25519/AES)={}, slow(ML-KEM/ML-DSA/composite)={}, warmup={}",
        FAST_ITERS, SLOW_ITERS, WARMUP
    );
    println!("available_parallelism (cores): {cores}");
    println!("signed-message size for sign/verify: {AUTH_MSG_LEN} bytes\n");

    let msg = vec![0xa5u8; AUTH_MSG_LEN];

    // ---------------------------------------------------------------- X25519
    let peer_secret = EphemeralSecret::random();
    let peer_pub = XPublicKey::from(&peer_secret);

    let x_keygen = bench(FAST_ITERS, || {
        let s = EphemeralSecret::random();
        let p = XPublicKey::from(&s);
        black_box((s, p));
    });
    // EphemeralSecret::diffie_hellman consumes self, so we can only time
    // (keygen + DH) together and derive DH by subtraction.
    let x_keygen_dh = bench(FAST_ITERS, || {
        let s = EphemeralSecret::random();
        let _p = XPublicKey::from(&s);
        let ss = s.diffie_hellman(&peer_pub);
        black_box(ss);
    });
    let x_dh_median = (x_keygen_dh.median - x_keygen.median).max(0.0);

    // ---------------------------------------------------------------- ML-KEM-768
    let (dk768, ek768) = MlKem768::generate(&mut OsRng);
    let (ct768, _ss768) = ek768.encapsulate(&mut OsRng).unwrap();
    let mlkem768_keygen = bench(SLOW_ITERS, || {
        let kp = MlKem768::generate(&mut OsRng);
        black_box(kp);
    });
    let mlkem768_encaps = bench(SLOW_ITERS, || {
        let r = ek768.encapsulate(&mut OsRng).unwrap();
        black_box(r);
    });
    let mlkem768_decaps = bench(SLOW_ITERS, || {
        let r = dk768.decapsulate(&ct768).unwrap();
        black_box(r);
    });

    // ---------------------------------------------------------------- ML-KEM-1024
    let (dk1024, ek1024) = MlKem1024::generate(&mut OsRng);
    let (ct1024, _ss1024) = ek1024.encapsulate(&mut OsRng).unwrap();
    let mlkem1024_keygen = bench(SLOW_ITERS, || {
        let kp = MlKem1024::generate(&mut OsRng);
        black_box(kp);
    });
    let mlkem1024_encaps = bench(SLOW_ITERS, || {
        let r = ek1024.encapsulate(&mut OsRng).unwrap();
        black_box(r);
    });
    let mlkem1024_decaps = bench(SLOW_ITERS, || {
        let r = dk1024.decapsulate(&ct1024).unwrap();
        black_box(r);
    });

    // ---------------------------------------------------------------- Ed25519
    let ed_sk = EdSigningKey::from_bytes(&[0x11u8; 32]);
    let ed_vk = ed_sk.verifying_key();
    let ed_sig = ed_sk.try_sign(&msg).unwrap();
    let ed_sign = bench(FAST_ITERS, || {
        let s = ed_sk.try_sign(&msg).unwrap();
        black_box(s);
    });
    let ed_verify = bench(FAST_ITERS, || {
        let ok = ed_vk.verify_strict(&msg, &ed_sig);
        black_box(ok.is_ok());
    });

    // ---------------------------------------------------------------- ML-DSA-65
    let ml_seed = MlDsaSeed::try_from(&[0x22u8; MLDSA65_SEED_LEN][..]).unwrap();
    let ml_sk = MlDsaSigningKey::<MlDsa65>::from_seed(&ml_seed);
    let ml_vk = ml_sk.verifying_key();
    let ml_sig: ml_dsa::Signature<MlDsa65> = ml_sk.try_sign(&msg).unwrap();
    let mldsa_keygen = bench(SLOW_ITERS, || {
        let s = MlDsaSigningKey::<MlDsa65>::from_seed(&ml_seed);
        black_box(s);
    });
    // ML-DSA signing uses rejection sampling: cost is message-dependent, so a
    // single fixed message gives an unrepresentative (lucky/unlucky) draw. A real
    // handshake signs a different auth message every connection, so vary the
    // message each iteration to capture the true average rejection cost.
    let mut sign_msg = msg.clone();
    let mut ctr = 0usize;
    let mldsa_sign = bench(SLOW_ITERS, || {
        sign_msg[ctr % AUTH_MSG_LEN] ^= 0xff;
        ctr = ctr.wrapping_add(1);
        let s: ml_dsa::Signature<MlDsa65> = ml_sk.try_sign(&sign_msg).unwrap();
        black_box(s);
    });
    let mldsa_verify = bench(SLOW_ITERS, || {
        let ok = ml_vk.verify(&msg, &ml_sig);
        black_box(ok.is_ok());
    });

    // ---------------------------------------------------------------- composite (real code path)
    // One resolve_identity == ONE IdentityMaterial::from_bytes with the peer's
    // public keys already in hand. Production reads the peer pubkey from env as
    // bytes; it does NOT re-derive the peer keypair. So precompute peer pubs once
    // (outside timing) and time only the from_bytes the handshake path runs.
    let load_ed_seed = [0x11u8; ED25519_SEED_LEN];
    let load_ml_seed = [0x22u8; MLDSA65_SEED_LEN];
    let peer_ed_pub = EdSigningKey::from_bytes(&[0x33u8; ED25519_SEED_LEN])
        .verifying_key()
        .to_bytes();
    let peer_ml_pub = MlDsaSigningKey::<MlDsa65>::from_seed(
        &MlDsaSeed::try_from(&[0x44u8; MLDSA65_SEED_LEN][..]).unwrap(),
    )
    .verifying_key()
    .encode()
    .as_slice()
    .to_vec();
    let id_load = bench(SLOW_ITERS, || {
        let m =
            IdentityMaterial::from_bytes(load_ed_seed, load_ml_seed, peer_ed_pub, peer_ml_pub.clone())
                .unwrap();
        black_box(m);
    });
    let one_load_median = id_load.median;

    let mut suite_sums = Vec::new();
    for (label, suite, wire_ms) in [
        ("0x01 (ML-KEM-768)", CipherSuite::NistStandard768, 1.37f64),
        ("0x02 (ML-KEM-1024)", CipherSuite::NistStandard1024, 1.49f64),
    ] {
        let (client, server) = identities();
        let engine = suite.engine();

        // Time each handshake phase using the crate's own production API.
        let mut begin = Vec::with_capacity(SLOW_ITERS);
        let mut respond = Vec::with_capacity(SLOW_ITERS);
        let mut finish = Vec::with_capacity(SLOW_ITERS);
        for _ in 0..WARMUP + SLOW_ITERS {
            let t0 = Instant::now();
            let (state, ch) = engine.begin_initiator(&client).unwrap();
            let t1 = Instant::now();
            let (sk, sh) = engine.respond(&server, &ch).unwrap();
            let t2 = Instant::now();
            let ck = state.finish(&client, &sh).unwrap();
            let t3 = Instant::now();
            black_box((sk, ck));
            begin.push((t1 - t0).as_secs_f64() * 1000.0);
            respond.push((t2 - t1).as_secs_f64() * 1000.0);
            finish.push((t3 - t2).as_secs_f64() * 1000.0);
        }
        let med = |v: &mut Vec<f64>| {
            v.drain(0..WARMUP);
            v.sort_by(|a, b| a.partial_cmp(b).unwrap());
            v[v.len() / 2]
        };
        let bm = med(&mut begin);
        let rm = med(&mut respond);
        let fm = med(&mut finish);
        // Production resolves identity 3x per handshake (begin, respond, finish).
        let loads = one_load_median * 3.0;
        let crypto_sum = bm + rm + fm + loads;
        suite_sums.push((label.to_string(), bm, rm, fm, loads, crypto_sum, wire_ms));
    }

    // ============================================================ output
    println!("== per-operation cost (ms) ==");
    println!(
        "{:<26} {:>8} {:>12} {:>12} {:>12}",
        "operation", "iters", "median", "p95", "max"
    );
    row("X25519 keygen", FAST_ITERS, &x_keygen);
    row("X25519 keygen+DH", FAST_ITERS, &x_keygen_dh);
    println!("{:<26} {:>8} {:>12.4} {:>12} {:>12}", "X25519 DH (derived)", FAST_ITERS, x_dh_median, "-", "-");
    row("ML-KEM-768 keygen", SLOW_ITERS, &mlkem768_keygen);
    row("ML-KEM-768 encaps", SLOW_ITERS, &mlkem768_encaps);
    row("ML-KEM-768 decaps", SLOW_ITERS, &mlkem768_decaps);
    row("ML-KEM-1024 keygen", SLOW_ITERS, &mlkem1024_keygen);
    row("ML-KEM-1024 encaps", SLOW_ITERS, &mlkem1024_encaps);
    row("ML-KEM-1024 decaps", SLOW_ITERS, &mlkem1024_decaps);
    row("Ed25519 sign", FAST_ITERS, &ed_sign);
    row("Ed25519 verify", FAST_ITERS, &ed_verify);
    row("ML-DSA-65 keygen(seed)", SLOW_ITERS, &mldsa_keygen);
    row("ML-DSA-65 sign", SLOW_ITERS, &mldsa_sign);
    row("ML-DSA-65 verify", SLOW_ITERS, &mldsa_verify);
    row("identity load (from_bytes)", SLOW_ITERS, &id_load);
    println!("  (one resolve_identity ~= {one_load_median:.4} ms; 3x per handshake)\n");

    println!("== per-suite handshake crypto sum (real begin/respond/finish + 3x identity load) ==");
    println!(
        "{:<20} {:>10} {:>10} {:>10} {:>12} {:>12} {:>10}",
        "suite", "begin", "respond", "finish", "3x id-load", "crypto-sum", "wire(G4)"
    );
    for (label, bm, rm, fm, loads, sum, wire) in &suite_sums {
        println!(
            "{:<20} {:>10.4} {:>10.4} {:>10.4} {:>12.4} {:>12.4} {:>10.2}",
            label, bm, rm, fm, loads, sum, wire
        );
    }

    println!("\n== reconciliation vs Gate 4 wire handshake ==");
    for (label, _bm, _rm, _fm, _loads, sum, wire) in &suite_sums {
        let gap = wire - sum;
        let pct = 100.0 * sum / wire;
        println!(
            "  {label}: crypto-sum {sum:.3} ms vs wire {wire:.2} ms  ->  \
             crypto is {pct:.0}% of wire; {gap:+.3} ms is framing/syscalls/RTT/AES",
        );
    }
}
