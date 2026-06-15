//! Fail-closed assurance — property & robustness tests.
//!
//! These prove the platform's load-bearing safety invariants by throwing large
//! volumes of random and adversarial input at the real code paths, with a
//! **seeded** RNG so every run is byte-for-byte reproducible. They are not a
//! substitute for Miri (UB) or a continuous fuzzing campaign (both require a
//! nightly toolchain absent from this environment — see
//! `docs/FAIL_CLOSED_VALIDATION.md`); they are the in-sandbox, deterministic
//! evidence for the invariants those tools would also exercise.
//!
//! Invariants asserted:
//!   I1  No cleartext on the wire: a known plaintext canary never survives into
//!       any byte stream the overlay emits (seal / record layer / fallback).
//!   I2  Tamper ⇒ fail closed: any mutation of an authenticated record makes
//!       `open` return `Err`, never plaintext.
//!   I3  Parsers never panic and never leak: arbitrary bytes into every wire
//!       parser yield `Err`/`None`/bounded-`Ok`, never a panic, never the canary.
//!   I4  Anti-replay never double-accepts: a sequence number is accepted at most
//!       once across any random delivery order.
//!   I5  Cookie has no false-accept: any mutation of a valid cookie is rejected.
//!
//! No fabricated numbers — every assertion is a real outcome of the real code.

use rand::rngs::StdRng;
use rand::{Rng, RngCore, SeedableRng};

use syntriass_overlay::crypto::{
    derive_fallback_session, derive_identity_public_keys, AntiReplayWindow, CipherSuite,
    IdentityMaterial, SessionLimits, ED25519_SEED_LEN, FALLBACK_NONCE_LEN, FALLBACK_PSK_LEN,
    MLDSA65_SEED_LEN,
};
use syntriass_overlay::handshake_guard::{Cookie, GuardConfig, HandshakeGuard, COOKIE_WIRE_LEN};
use syntriass_overlay::kernel_native::KernelSockEvent;

/// A distinctive plaintext canary that must NEVER appear in any emitted bytes.
const CANARY: &[u8] = b"SYNTRIASS::CLEARTEXT::CANARY::e3b0c44298fc1c14";

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || haystack.len() < needle.len() {
        return false;
    }
    haystack.windows(needle.len()).any(|w| w == needle)
}

/// A plaintext of random length that embeds the canary at a random offset.
fn canary_plaintext(rng: &mut StdRng) -> Vec<u8> {
    let pad_before = rng.gen_range(0..64);
    let pad_after = rng.gen_range(0..64);
    let mut pt = Vec::with_capacity(pad_before + CANARY.len() + pad_after);
    pt.resize(pad_before, 0);
    rng.fill_bytes(&mut pt);
    pt.extend_from_slice(CANARY);
    let mut tail = vec![0u8; pad_after];
    rng.fill_bytes(&mut tail);
    pt.extend_from_slice(&tail);
    pt
}

fn fallback_session(initiator: bool) -> syntriass_overlay::crypto::SessionKeys {
    let psk = [0x5au8; FALLBACK_PSK_LEN];
    let cn = [0x01u8; FALLBACK_NONCE_LEN];
    let sn = [0x02u8; FALLBACK_NONCE_LEN];
    derive_fallback_session(&psk, &cn, &sn, initiator).unwrap()
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

#[test]
fn i1_no_cleartext_canary_in_sealed_records() {
    let mut rng = StdRng::seed_from_u64(0xF00D_1111);
    // Sanity: the canary really is in the plaintext we feed in.
    assert!(contains(CANARY, CANARY));

    let mut session = fallback_session(true).into_secure_session(SessionLimits::default());
    let mut emitted = 0u64;
    for _ in 0..20_000 {
        let pt = canary_plaintext(&mut rng);
        assert!(
            contains(&pt, CANARY),
            "test setup: plaintext must hold canary"
        );
        let record = session.seal(&pt).unwrap();
        assert!(
            !contains(&record, CANARY),
            "CLEARTEXT LEAK: canary survived into a sealed record"
        );
        emitted += 1;
    }
    eprintln!("[I1 no-cleartext ] sealed_records={emitted} canary_leaks=0");
}

#[test]
fn i2_any_tamper_fails_closed() {
    let mut rng = StdRng::seed_from_u64(0xF00D_2222);
    let limits = SessionLimits::default();
    let mut tx = fallback_session(true).into_secure_session(limits);
    let mut rx = fallback_session(false).into_secure_session(limits);

    let mut checked = 0u64;
    for _ in 0..20_000 {
        let pt = canary_plaintext(&mut rng);
        let good = tx.seal(&pt).unwrap();
        // Control: an untampered record opens to exactly the plaintext.
        let opened = rx.open(&good).expect("genuine record opens");
        assert_eq!(opened, pt);

        // Tamper: flip a random bit somewhere in the record.
        let mut bad = good.clone();
        let byte = rng.gen_range(0..bad.len());
        let bit = 1u8 << rng.gen_range(0..8);
        bad[byte] ^= bit;
        if bad == good {
            continue;
        }
        match rx.open(&bad) {
            Err(_) => {}
            Ok(leak) => panic!(
                "FAIL-OPEN: tampered record opened; canary_present={}",
                contains(&leak, CANARY)
            ),
        }
        checked += 1;
    }
    eprintln!("[I2 tamper       ] tampered_records={checked} fail_open=0");
}

#[test]
fn i3_parsers_never_panic_and_never_leak() {
    let mut rng = StdRng::seed_from_u64(0xF00D_3333);
    let (_client, server) = trusting_identities();
    let engine = CipherSuite::NistStandard768.engine();
    let mut rx = fallback_session(false).into_secure_session(SessionLimits::default());

    let mut fed = 0u64;
    for _ in 0..50_000 {
        // Random length, random content — the adversary's free input.
        let len = rng.gen_range(0..512);
        let mut buf = vec![0u8; len];
        rng.fill_bytes(&mut buf);
        // Occasionally splice the canary in, to prove no parser ever echoes it.
        if rng.gen_ratio(1, 8) && len >= CANARY.len() {
            let at = rng.gen_range(0..=len - CANARY.len());
            buf[at..at + CANARY.len()].copy_from_slice(CANARY);
        }

        // Cookie parser: Some only at the exact wire length; never panics.
        if Cookie::from_bytes(&buf).is_some() {
            assert_eq!(buf.len(), COOKIE_WIRE_LEN);
        }

        // Kernel event parser: Some only at the exact wire length; its
        // serialization is canonical (parse∘serialize is idempotent) and is
        // always exactly WIRE_LEN bytes — never panics, never grows unbounded.
        match KernelSockEvent::from_bytes(&buf) {
            Some(ev) => {
                // Accepts a fixed 56-byte record (ignoring any trailing bytes).
                assert!(buf.len() >= KernelSockEvent::WIRE_LEN);
                let once = ev.to_bytes();
                assert_eq!(once.len(), KernelSockEvent::WIRE_LEN);
                let twice = KernelSockEvent::from_bytes(&once).unwrap().to_bytes();
                assert_eq!(once, twice, "kernel-event serialization must be canonical");
            }
            None => assert!(buf.len() < KernelSockEvent::WIRE_LEN),
        }

        // Record opener: arbitrary bytes must fail closed, never return the canary.
        if let Ok(pt) = rx.open(&buf) {
            assert!(
                !contains(&pt, CANARY),
                "parser leaked the canary out of random input"
            );
        }

        // Hybrid responder: arbitrary bytes as a ClientHello must Err, not panic.
        assert!(
            engine.respond(&server, &buf).is_err(),
            "random bytes must never be accepted as a valid ClientHello"
        );
        fed += 1;
    }
    eprintln!("[I3 parsers      ] random_inputs={fed} panics=0 leaks=0");
}

#[test]
fn i4_anti_replay_never_double_accepts() {
    let mut rng = StdRng::seed_from_u64(0xF00D_4444);
    // Many independent windows, each driven by a random delivery order.
    for _ in 0..200 {
        let mut window = AntiReplayWindow::new();
        let mut accepted_once = std::collections::HashSet::new();
        // A stream of sequence numbers with heavy reuse and reordering.
        let span = rng.gen_range(8..256u64);
        for _ in 0..2_000 {
            let seq = rng.gen_range(0..span);
            if window.commit(seq) {
                assert!(
                    accepted_once.insert(seq),
                    "anti-replay DOUBLE-ACCEPTED seq {seq}"
                );
            }
        }
    }
    eprintln!("[I4 anti-replay  ] windows=200 ops=400000 double_accepts=0");
}

#[test]
fn i5_cookie_has_no_false_accept_under_mutation() {
    let mut rng = StdRng::seed_from_u64(0xF00D_5555);
    let source = b"203.0.113.42";
    let now = 1_000u64;

    let mut mutations = 0u64;
    for _ in 0..20_000 {
        // Fresh guard each round so the genuine control is always admissible and
        // a mutation can never "win" by colliding with a consumed tag.
        let mut guard = HandshakeGuard::new(GuardConfig::default(), now);
        let cookie = guard.request(source, now).unwrap();
        let good = cookie.to_bytes();

        // Mutate 1..=4 random bytes.
        let mut bad = good;
        let n = rng.gen_range(1..=4);
        for _ in 0..n {
            let idx = rng.gen_range(0..bad.len());
            bad[idx] ^= 1u8 << rng.gen_range(0..8);
        }
        if bad == good {
            continue;
        }
        if let Some(forged) = Cookie::from_bytes(&bad) {
            assert!(
                guard.admit(source, &forged, now).is_err(),
                "FALSE ACCEPT: a mutated cookie was admitted"
            );
        }
        mutations += 1;
    }
    eprintln!("[I5 cookie       ] mutations={mutations} false_accepts=0");
}

#[test]
fn i1b_no_cleartext_in_full_pqc_records() {
    // The same no-cleartext invariant over the real hybrid-PQC session (both
    // suites), at a lower iteration count since the handshake is expensive.
    let mut rng = StdRng::seed_from_u64(0xF00D_6666);
    for suite in [CipherSuite::NistStandard768, CipherSuite::NistStandard1024] {
        let (client_id, server_id) = trusting_identities();
        let engine = suite.engine();
        let (state, hello) = engine.begin_initiator(&client_id).unwrap();
        let (server_keys, server_hello) = engine.respond(&server_id, &hello).unwrap();
        let client_keys = state.finish(&client_id, &server_hello).unwrap();
        let mut c = client_keys.into_secure_session(SessionLimits::default());
        let mut s = server_keys.into_secure_session(SessionLimits::default());
        for _ in 0..500 {
            let pt = canary_plaintext(&mut rng);
            let rec = c.seal(&pt).unwrap();
            assert!(!contains(&rec, CANARY), "{suite:?}: canary leaked");
            assert_eq!(s.open(&rec).unwrap(), pt);
        }
    }
    eprintln!("[I1b pqc-cleartext] suites=2 records=1000 canary_leaks=0");
}
