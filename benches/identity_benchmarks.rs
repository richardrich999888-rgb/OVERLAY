//! Identity-lifecycle micro-benchmarks (latencies + artifact sizes).
//!
//! Standalone binary (`harness = false`), like `demo_benchmarks`. Times the
//! per-operation cost of the hybrid Ed25519 + ML-DSA-65 credential lifecycle and
//! prints the on-wire sizes. Pure CPU; reproducible with `cargo bench --bench
//! identity_benchmarks`. Numbers are host-dependent (shared sandbox here) — they
//! localise cost, they are not a target-hardware claim.

use std::time::Instant;

use syntriass_overlay::identity::{
    EnrollmentRequest, IssuingAuthority, RecoveryAuthorization, SoftwareSigner, TrustStore,
};

fn median_us(mut samples: Vec<f64>) -> f64 {
    samples.sort_by(|a, b| a.partial_cmp(b).unwrap());
    samples[samples.len() / 2]
}

fn time<F: FnMut()>(iters: usize, mut f: F) -> f64 {
    // warm up
    for _ in 0..(iters / 10).max(1) {
        f();
    }
    let mut s = Vec::with_capacity(iters);
    for _ in 0..iters {
        let t = Instant::now();
        f();
        s.push(t.elapsed().as_secs_f64() * 1e6);
    }
    median_us(s)
}

fn main() {
    let n = 200;

    // Fixed CA + a pre-generated node signer to isolate each op.
    let ca = IssuingAuthority::new(SoftwareSigner::from_seeds([1u8; 32], [2u8; 32]).unwrap());
    let ca_pub = ca.public();
    let node_signer = SoftwareSigner::from_seeds([3u8; 32], [4u8; 32]).unwrap();
    let node_id = [0x33u8; 16];

    // Enrollment = fresh hybrid keygen + proof-of-possession self-sign.
    let enroll_us = time(n, || {
        let s = SoftwareSigner::generate();
        let _ = EnrollmentRequest::create(node_id, &s).unwrap();
    });

    // Proof-of-possession verify (CA side, before issuing).
    let req = EnrollmentRequest::create(node_id, &node_signer).unwrap();
    let pop_us = time(n, || {
        req.verify_proof_of_possession().unwrap();
    });

    // Issue = CA hybrid sign over the credential body.
    let issue_us = time(n, || {
        let _ = ca.issue(&req, 1, 0, 1_000, 9_000).unwrap();
    });

    // Verify = 2 sig verifies + window + floor + (no) revocation.
    let cred = ca.issue(&req, 1, 0, 1_000, 9_000).unwrap();
    let store = TrustStore::new(ca_pub.clone());
    let verify_us = time(n, || {
        store.verify(&cred, 1_500).unwrap();
    });

    // Revoke = CA hybrid sign over a CRL body.
    let revoke_us = time(n, || {
        let _ = ca.revoke(&[1, 2, 3, 4, 5], 1, 1_000, 9_000).unwrap();
    });

    // Recovery authorization = CA hybrid sign over a small body.
    let recov_us = time(n, || {
        let _ = ca.authorize_recovery(node_id, 1, 1_000).unwrap();
    });

    // Artifact sizes (bytes on the wire / on a courier USB).
    let req_sz = req.to_bytes().len();
    let cred_sz = cred.to_bytes().len();
    let crl_sz = ca
        .revoke(&[1, 2, 3], 1, 1_000, 9_000)
        .unwrap()
        .to_bytes()
        .len();
    let authz_sz: usize = ca
        .authorize_recovery(node_id, 1, 1_000)
        .unwrap()
        .to_bytes()
        .len();
    let _ = RecoveryAuthorization::from_bytes(
        &ca.authorize_recovery(node_id, 1, 1_000).unwrap().to_bytes(),
    )
    .unwrap();

    println!("== SYNTRIASS identity-lifecycle benchmarks (median of n={n}) ==");
    println!("operation                         median latency");
    println!("  enrollment (keygen + PoP sign)   {enroll_us:9.1} us");
    println!("  proof-of-possession verify       {pop_us:9.1} us");
    println!("  issue credential (CA sign)       {issue_us:9.1} us");
    println!("  verify credential (relying peer) {verify_us:9.1} us");
    println!("  issue revocation list (CA sign)  {revoke_us:9.1} us");
    println!("  authorize recovery (CA sign)     {recov_us:9.1} us");
    println!();
    println!("artifact                          size (bytes)");
    println!("  enrollment request               {req_sz:6}");
    println!("  identity credential              {cred_sz:6}");
    println!("  revocation list (3 serials)      {crl_sz:6}");
    println!("  recovery authorization           {authz_sz:6}");
}
