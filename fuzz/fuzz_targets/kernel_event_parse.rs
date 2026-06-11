//! Fuzz the kernel-event RingBuf record parser: arbitrary bytes must never
//! panic; parsing is canonical. (Host-only; see fuzz/README.md.)
#![no_main]
use libfuzzer_sys::fuzz_target;
use syntriass_overlay::kernel_native::KernelSockEvent;

fuzz_target!(|data: &[u8]| {
    if let Some(ev) = KernelSockEvent::from_bytes(data) {
        assert!(data.len() >= KernelSockEvent::WIRE_LEN);
        let once = ev.to_bytes();
        let twice = KernelSockEvent::from_bytes(&once).unwrap().to_bytes();
        assert_eq!(once, twice);
    }
});
