#![no_std]

//! Shared kernel/user-space map types for the Syntriass eBPF data plane.
//!
//! `SockEvent` MUST stay byte-for-byte identical to
//! `syntriass_overlay::kernel_native::KernelSockEvent` (same field order, all
//! `#[repr(C)]`, 56 bytes) — the eBPF program writes it into the RingBuf and the
//! user-space daemon decodes it with `KernelSockEvent::from_bytes`.

/// Connection event streamed to user space via the RingBuf. 56 bytes.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SockEvent {
    pub cookie: u64,
    pub cgroup_id: u64,
    pub src_addr: [u8; 16],
    pub dst_addr: [u8; 16],
    pub src_port: u16,
    pub dst_port: u16,
    pub family: u16,
    pub _pad: u16,
}

// Compile-time ABI guard mirroring `kernel_native::KernelSockEvent` in user
// space. If the kernel struct drifts, the eBPF crate fails to compile.
const _: () = {
    use core::mem::{align_of, offset_of, size_of};
    assert!(size_of::<SockEvent>() == 56, "SockEvent must be 56 bytes");
    assert!(align_of::<SockEvent>() == 8, "SockEvent must be 8-byte aligned");
    assert!(offset_of!(SockEvent, cookie) == 0);
    assert!(offset_of!(SockEvent, cgroup_id) == 8);
    assert!(offset_of!(SockEvent, src_addr) == 16);
    assert!(offset_of!(SockEvent, dst_addr) == 32);
    assert!(offset_of!(SockEvent, src_port) == 48);
    assert!(offset_of!(SockEvent, dst_port) == 50);
    assert!(offset_of!(SockEvent, family) == 52);
    assert!(offset_of!(SockEvent, _pad) == 54);
};

/// Retained per-socket enforcement metadata (kept in a SockHash/SockMap).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SecureSocket {
    pub socket_id: u64,
    pub local_port: u16,
    pub remote_port: u16,
    pub cgroup_id: u64,
    pub flags: u32,
}

/// Atomic counters exposed for telemetry (read by the user-space metrics layer).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct KernelCounters {
    pub active_sessions: u64,
    pub bypass_attempts: u64,
    pub upcalls: u64,
    pub failures: u64,
}

pub const SOCKET_FLAG_PQC_REQUIRED: u32 = 1 << 0;
pub const SOCKET_FLAG_KTLS_READY: u32 = 1 << 1;

/// Address families as the verifier sees them (mirror of libc).
pub const AF_INET: u32 = 2;
pub const AF_INET6: u32 = 10;
