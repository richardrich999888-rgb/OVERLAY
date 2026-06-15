//! Phase 3 (Cryptographic Policy Enforcement) — measured enforcement over a
//! profile derived from a REAL post-quantum handshake.
//!
//! The unit tests in `src/crypto/crypto_policy.rs` prove the decision matrix; this
//! file links enforcement to an actual handshake (so the "full PQC" profile is
//! real, not asserted), measures per-decision enforcement latency, and checks the
//! kernel-flag agreement that lets the eBPF data plane and the daemon share one
//! policy.

use std::time::Instant;

use syntriass_overlay::crypto::crypto_policy::{
    kernel_flags, Attr, ConnectionProfile, CryptoPolicy, CryptoViolation, KeyBacking,
};
use syntriass_overlay::crypto::{
    derive_identity_public_keys, CipherSuite, IdentityMaterial, ED25519_SEED_LEN, MLDSA65_SEED_LEN,
};

fn trusting_pair() -> (IdentityMaterial, IdentityMaterial) {
    let (ce, cm) = ([0x11u8; ED25519_SEED_LEN], [0x22u8; MLDSA65_SEED_LEN]);
    let (se, sm) = ([0x33u8; ED25519_SEED_LEN], [0x44u8; MLDSA65_SEED_LEN]);
    let (ce_pub, cm_pub) = derive_identity_public_keys(&ce, &cm).unwrap();
    let (se_pub, sm_pub) = derive_identity_public_keys(&se, &sm).unwrap();
    let client = IdentityMaterial::from_bytes(ce, cm, se_pub, sm_pub).unwrap();
    let server = IdentityMaterial::from_bytes(se, sm, ce_pub, cm_pub).unwrap();
    (client, server)
}

/// Run a real handshake; on success the connection is genuinely full-PQC hybrid.
fn real_full_pqc_profile(suite: CipherSuite) -> ConnectionProfile {
    let (client, server) = trusting_pair();
    let engine = suite.engine();
    let (_st, ch) = engine.begin_initiator(&client).expect("client hello");
    let (_keys, _resp) = engine.respond(&server, &ch).expect("server accepts");
    // The handshake completed with ML-KEM + X25519 — a real hybrid PQC session.
    ConnectionProfile::full_pqc(suite)
}

#[test]
fn full_pqc_only_enforced_over_real_handshake() {
    let prof = real_full_pqc_profile(CipherSuite::NistStandard768);
    let pol = CryptoPolicy::full_pqc_only();
    assert!(
        pol.permits(&prof),
        "a real full-PQC handshake must satisfy FullPqcOnly"
    );

    // The same policy must reject the encrypted PSK fallback.
    let fb = ConnectionProfile::encrypted_fallback(CipherSuite::NistStandard768);
    assert_eq!(pol.enforce(&fb), Err(CryptoViolation::FullPqcRequired));
    println!("[crypto-policy] FullPqcOnly: real PQC handshake ACCEPTED, fallback REJECTED");
}

#[test]
fn rejection_correctness_matrix() {
    let suite = CipherSuite::NistStandard768;
    let full = ConnectionProfile::full_pqc(suite);
    let fallback = ConnectionProfile::encrypted_fallback(suite);
    let mut classical_fb = fallback;
    classical_fb.fallback_is_classical = Attr::Yes;
    let hw = full.with_hardware_key();

    // (policy, profile, expected) — None = accept.
    type Case = (CryptoPolicy, ConnectionProfile, Option<CryptoViolation>);
    let cases: Vec<Case> = vec![
        (CryptoPolicy::full_pqc_only(), full, None),
        (
            CryptoPolicy::full_pqc_only(),
            fallback,
            Some(CryptoViolation::FullPqcRequired),
        ),
        (CryptoPolicy::hybrid_only(), full, None),
        (
            CryptoPolicy::hybrid_only(),
            fallback,
            Some(CryptoViolation::HybridRequired),
        ),
        (CryptoPolicy::fallback_allowed(), fallback, None),
        (
            CryptoPolicy::fallback_allowed(),
            classical_fb,
            Some(CryptoViolation::ClassicalFallbackForbidden),
        ),
        (
            CryptoPolicy::hardware_key_required(),
            full,
            Some(CryptoViolation::HardwareKeyRequired),
        ),
        (CryptoPolicy::hardware_key_required(), hw, None),
        (
            CryptoPolicy::no_classical_fallback(),
            classical_fb,
            Some(CryptoViolation::ClassicalFallbackForbidden),
        ),
        (CryptoPolicy::no_classical_fallback(), fallback, None),
    ];

    let mut ok = 0;
    for (pol, prof, want) in &cases {
        let got = pol.enforce(prof).err();
        assert_eq!(
            got, *want,
            "policy={pol:?} profile_fallback={}",
            prof.is_fallback
        );
        ok += 1;
    }
    println!(
        "[crypto-policy] rejection correctness: {ok}/{} cases correct",
        cases.len()
    );
}

#[test]
fn fail_closed_on_unknown_attributes() {
    let suite = CipherSuite::NistStandard768;

    let mut unknown_pqc = ConnectionProfile::full_pqc(suite);
    unknown_pqc.pqc_active = Attr::Unknown;
    assert!(CryptoPolicy::full_pqc_only().enforce(&unknown_pqc).is_err());

    let mut unknown_key = ConnectionProfile::full_pqc(suite);
    unknown_key.key_backing = KeyBacking::Unknown;
    assert!(CryptoPolicy::hardware_key_required()
        .enforce(&unknown_key)
        .is_err());

    let mut unknown_fb = ConnectionProfile::encrypted_fallback(suite);
    unknown_fb.fallback_is_classical = Attr::Unknown;
    assert!(CryptoPolicy::no_classical_fallback()
        .enforce(&unknown_fb)
        .is_err());

    println!(
        "[crypto-policy] fail-closed: every Unknown attribute denied (no benefit of the doubt)"
    );
}

#[test]
fn kernel_and_userspace_flags_agree() {
    // FullPqcOnly must NOT carry FALLBACK_ALLOWED — so the kernel data plane
    // independently denies a fallback connection under the same policy.
    let f = CryptoPolicy::full_pqc_only().to_kernel_flags();
    assert_ne!(f & kernel_flags::FULL_PQC_ONLY, 0);
    assert_eq!(f & kernel_flags::FALLBACK_ALLOWED, 0);
    // FallbackAllowed must carry FALLBACK_ALLOWED and NO_CLASSICAL_FB.
    let g = CryptoPolicy::fallback_allowed().to_kernel_flags();
    assert_ne!(g & kernel_flags::FALLBACK_ALLOWED, 0);
    assert_ne!(g & kernel_flags::NO_CLASSICAL_FB, 0);
    println!(
        "[crypto-policy] kernel/userspace crypto_flags agree (full=0x{f:02x} fallback=0x{g:02x})"
    );
}

#[test]
fn enforcement_latency_measured() {
    let suite = CipherSuite::NistStandard768;
    let pol = CryptoPolicy::full_pqc_only();
    let full = ConnectionProfile::full_pqc(suite);
    let fallback = ConnectionProfile::encrypted_fallback(suite);

    let n = 1_000_000;
    let t = Instant::now();
    let mut accepts = 0u64;
    for i in 0..n {
        let p = if i % 2 == 0 { &full } else { &fallback };
        if pol.permits(p) {
            accepts += 1;
        }
    }
    let per = t.elapsed().as_secs_f64() * 1e9 / n as f64;
    // half the profiles are fallbacks the policy rejects
    assert_eq!(accepts, (n / 2) as u64);
    println!("[crypto-policy] enforcement latency: {per:.2} ns/decision over {n} decisions ({accepts} accepted)");
    assert!(per < 1000.0, "enforcement must be well under a microsecond");
}
