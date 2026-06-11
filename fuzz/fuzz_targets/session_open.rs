//! Fuzz the hardened record opener: arbitrary bytes into `SecureSession::open`
//! must fail closed (never panic, never return a plaintext canary).
//! (Host-only; see fuzz/README.md.)
#![no_main]
use libfuzzer_sys::fuzz_target;
use once_cell::sync::Lazy;
use std::sync::Mutex;
use syntriass_overlay::crypto::{derive_fallback_session, SecureSession, SessionLimits};

const CANARY: &[u8] = b"SYNTRIASS::CLEARTEXT::CANARY::e3b0c44298fc1c14";

static RX: Lazy<Mutex<SecureSession>> = Lazy::new(|| {
    let psk = [0x5au8; 32];
    let (cn, sn) = ([0x01u8; 16], [0x02u8; 16]);
    let keys = derive_fallback_session(&psk, &cn, &sn, false).unwrap();
    Mutex::new(keys.into_secure_session(SessionLimits::default()))
});

fuzz_target!(|data: &[u8]| {
    let mut rx = RX.lock().unwrap();
    if let Ok(pt) = rx.open(data) {
        assert!(
            !pt.windows(CANARY.len()).any(|w| w == CANARY),
            "record opener leaked the canary out of fuzz input"
        );
    }
});
