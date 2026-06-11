//! Fuzz the admission-cookie wire parser: arbitrary bytes must never panic and
//! may only parse at the exact wire length. (Host-only; see fuzz/README.md.)
#![no_main]
use libfuzzer_sys::fuzz_target;
use syntriass_overlay::handshake_guard::{Cookie, COOKIE_WIRE_LEN};

fuzz_target!(|data: &[u8]| {
    if let Some(c) = Cookie::from_bytes(data) {
        assert_eq!(data.len(), COOKIE_WIRE_LEN);
        // Re-serialization is canonical and exactly the wire length.
        let bytes = c.to_bytes();
        assert_eq!(bytes.len(), COOKIE_WIRE_LEN);
        assert_eq!(Cookie::from_bytes(&bytes), Some(c));
    }
});
