use crate::audit::events::KernelFlowEvent;

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FlowKey {
    pub cgroup_id: u64,
    pub pid: u32,
    pub tgid: u32,
    pub family: u32,
    pub protocol: u32,
    pub dst_addr: [u8; 16],
    pub dst_port: u16,
    pub _pad: u16,
}

const _: () = {
    use core::mem::{align_of, offset_of, size_of};
    assert!(size_of::<FlowKey>() == 48, "FlowKey must be 48 bytes");
    assert!(align_of::<FlowKey>() == 8, "FlowKey must be 8-byte aligned");
    assert!(offset_of!(FlowKey, cgroup_id) == 0);
    assert!(offset_of!(FlowKey, pid) == 8);
    assert!(offset_of!(FlowKey, tgid) == 12);
    assert!(offset_of!(FlowKey, family) == 16);
    assert!(offset_of!(FlowKey, protocol) == 20);
    assert!(offset_of!(FlowKey, dst_addr) == 24);
    assert!(offset_of!(FlowKey, dst_port) == 40);
    assert!(offset_of!(FlowKey, _pad) == 42);
};

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PendingFlow {
    pub first_seen_ns: u64,
    pub state: u32,
    pub _pad: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IdentityRecord {
    pub identity_id: u64,
    pub flags: u32,
    pub _pad: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PolicyKey {
    pub cgroup_id: u64,
    pub family: u32,
    pub dst_ip: [u8; 16],
    pub dst_port: u16,
}

const _: () = {
    use core::mem::{align_of, offset_of, size_of};
    assert!(size_of::<PolicyKey>() == 32, "PolicyKey must be 32 bytes");
    assert!(
        align_of::<PolicyKey>() == 8,
        "PolicyKey must be 8-byte aligned"
    );
    assert!(offset_of!(PolicyKey, cgroup_id) == 0);
    assert!(offset_of!(PolicyKey, family) == 8);
    assert!(offset_of!(PolicyKey, dst_ip) == 12);
    assert!(offset_of!(PolicyKey, dst_port) == 28);
};

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PolicyValue {
    pub action: u8,
}

#[cfg(target_os = "linux")]
unsafe impl aya::Pod for PolicyKey {}

#[cfg(target_os = "linux")]
unsafe impl aya::Pod for PolicyValue {}

const _: () = {
    use core::mem::{align_of, offset_of, size_of};
    assert!(size_of::<PolicyValue>() == 1, "PolicyValue must be 1 byte");
    assert!(
        align_of::<PolicyValue>() == 1,
        "PolicyValue must be 1-byte aligned"
    );
    assert!(offset_of!(PolicyValue, action) == 0);
};

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionValue {
    pub session_id: [u8; 32],
    pub session_state: u32,
    pub expires_at: u64,
}

#[cfg(target_os = "linux")]
unsafe impl aya::Pod for SessionValue {}

const _: () = {
    use core::mem::{align_of, offset_of, size_of};
    assert!(
        size_of::<SessionValue>() == 48,
        "SessionValue must be 48 bytes"
    );
    assert!(
        align_of::<SessionValue>() == 8,
        "SessionValue must be 8-byte aligned"
    );
    assert!(offset_of!(SessionValue, session_id) == 0);
    assert!(offset_of!(SessionValue, session_state) == 32);
    assert!(offset_of!(SessionValue, expires_at) == 40);
};

pub const POLICY_ALLOW: u8 = 1;
pub const POLICY_DENY: u8 = 2;
pub const SESSION_PENDING: u32 = 1;
pub const SESSION_PQC_NEGOTIATING: u32 = 2;
pub const SESSION_PQC_ESTABLISHED: u32 = 3;
pub const SESSION_EXPIRED: u32 = 4;
pub const EVENTS: &str = "EVENTS";
pub const FLOW_PENDING_MAP: &str = "FLOW_PENDING_MAP";
pub const IDENTITY_MAP: &str = "IDENTITY_MAP";
pub const AUDIT_RINGBUF: &str = "AUDIT_RINGBUF";
pub const POLICY_MAP: &str = "POLICY_MAP";
pub const SESSION_MAP: &str = "SESSION_MAP";

#[allow(dead_code)]
pub fn assert_shared_abi() {
    let _ = core::mem::size_of::<FlowKey>();
    let _ = core::mem::size_of::<PendingFlow>();
    let _ = core::mem::size_of::<IdentityRecord>();
    let _ = core::mem::size_of::<PolicyKey>();
    let _ = core::mem::size_of::<PolicyValue>();
    let _ = core::mem::size_of::<SessionValue>();
    let _ = core::mem::size_of::<KernelFlowEvent>();
}
