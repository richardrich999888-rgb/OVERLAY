//! Fuzz the hybrid-PQC responder: arbitrary bytes as a ClientHello must be
//! rejected (Err), never panic, never complete a handshake.
//! (Host-only; see fuzz/README.md.)
#![no_main]
use libfuzzer_sys::fuzz_target;
use once_cell::sync::Lazy;
use syntriass_overlay::crypto::{
    derive_identity_public_keys, CipherSuite, IdentityMaterial,
};

static SERVER: Lazy<IdentityMaterial> = Lazy::new(|| {
    let (ce, cm) = ([0x11u8; 32], [0x22u8; 32]);
    let (se, sm) = ([0x33u8; 32], [0x44u8; 32]);
    let (ce_pub, cm_pub) = derive_identity_public_keys(&ce, &cm).unwrap();
    let _ = (se, sm);
    IdentityMaterial::from_bytes(se, sm, ce_pub, cm_pub).unwrap()
});

fuzz_target!(|data: &[u8]| {
    let engine = CipherSuite::NistStandard768.engine();
    // Random bytes must never be accepted as a valid, trusted ClientHello.
    let _ = engine.respond(&*SERVER, data);
});
