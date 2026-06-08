#![no_std]

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SecureSocket {
    pub socket_id: u64,
    pub local_port: u16,
    pub remote_port: u16,
    pub cgroup_id: u64,
    pub flags: u32,
}

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
