//! Rust binding to the C-DAC ParaS (SYCL 2020) offload bridge.
//!
//! Enabled by the `cdac-accel` feature, which makes `build.rs` compile
//! `src/accelerator/cdac_sycl_bridge.cpp` (via the `cc` crate) and link it into
//! the crate. The C side asserts the 56-byte ABI at compile time; this side
//! hands it the same `KernelSockEvent` bytes the eBPF RingBuf carries.

use std::ffi::CStr;
use std::os::raw::c_char;

use crate::kernel_native::KernelSockEvent;

extern "C" {
    fn cdac_sycl_evaluate(buf: *const u8, len: usize, out_trace_hash: *mut u64) -> i32;
    fn cdac_sycl_backend_name() -> *const c_char;
}

/// Name of the active offload backend (`parascc-sycl2020` or `host-fallback`).
pub fn backend_name() -> String {
    // SAFETY: the C function returns a pointer to a static NUL-terminated string.
    unsafe {
        CStr::from_ptr(cdac_sycl_backend_name())
            .to_string_lossy()
            .into_owned()
    }
}

/// Offload an out-of-band evaluation of one 56-byte event to the C-DAC SYCL
/// queue, returning the connection-trace hash. `Err(rc)` is a fail-closed code
/// (`CDAC_ERR_*`, negative) the caller must treat as an abort.
pub fn evaluate(event: &KernelSockEvent) -> Result<u64, i32> {
    let bytes = event.to_bytes();
    let mut out: u64 = 0;
    // SAFETY: `bytes` is exactly `KernelSockEvent::WIRE_LEN` (56) bytes, matching
    // the C side's strict length check; `out` is a valid writable u64.
    let rc = unsafe { cdac_sycl_evaluate(bytes.as_ptr(), bytes.len(), &mut out) };
    if rc == 0 {
        Ok(out)
    } else {
        Err(rc)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fnv1a(bytes: &[u8]) -> u64 {
        let mut h: u64 = 1469598103934665603;
        for &b in bytes {
            h ^= b as u64;
            h = h.wrapping_mul(1099511628211);
        }
        h
    }

    #[test]
    fn evaluates_56_byte_event_through_the_bridge() {
        let mut dst = [0u8; 16];
        dst[..4].copy_from_slice(&[93, 184, 216, 34]);
        let ev = KernelSockEvent {
            cookie: 0xDEAD_BEEF,
            cgroup_id: 1234,
            src_addr: [0u8; 16],
            dst_addr: dst,
            src_port: 51000,
            dst_port: 443,
            family: libc::AF_INET as u16,
            _pad: 0,
        };
        let hash = evaluate(&ev).expect("host-fallback evaluation must succeed");
        assert_eq!(
            hash,
            fnv1a(&ev.to_bytes()),
            "trace hash must match the FNV-1a contract"
        );
        assert!(!backend_name().is_empty());
    }
}
