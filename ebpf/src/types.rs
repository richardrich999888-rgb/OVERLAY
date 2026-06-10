pub const FLOW_STATE_PENDING: u32 = 1;
pub const AUDIT_EVENT_CONNECT4: u32 = 1;
pub const AUDIT_EVENT_CONNECT6: u32 = 2;
pub const AUDIT_DECISION_ALLOW: u32 = 1;
#[allow(dead_code)]
pub const AUDIT_DECISION_DENY: u32 = 2;
pub const ACTION_ALLOW: u8 = 1;
pub const ACTION_DENY: u8 = 2;
pub const REASON_POLICY_ALLOW: u8 = 1;
pub const REASON_POLICY_DENY: u8 = 2;
pub const REASON_NO_POLICY: u8 = 3;
pub const POLICY_ALLOW: u8 = 1;
pub const POLICY_DENY: u8 = 2;
#[allow(dead_code)]
pub const SESSION_PENDING: u32 = 1;
#[allow(dead_code)]
pub const SESSION_PQC_NEGOTIATING: u32 = 2;
pub const SESSION_PQC_ESTABLISHED: u32 = 3;
#[allow(dead_code)]
pub const SESSION_EXPIRED: u32 = 4;

#[repr(C)]
#[derive(Clone, Copy)]
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
#[derive(Clone, Copy)]
pub struct PendingFlow {
    pub first_seen_ns: u64,
    pub state: u32,
    pub _pad: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct IdentityRecord {
    pub identity_id: u64,
    pub flags: u32,
    pub _pad: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct PolicyKey {
    pub cgroup_id: u64,
    pub family: u32,
    pub dst_ip: [u8; 16],
    pub dst_port: u16,
}

const _: () = {
    use core::mem::{align_of, offset_of, size_of};
    assert!(size_of::<PolicyKey>() == 32, "PolicyKey must be 32 bytes");
    assert!(align_of::<PolicyKey>() == 8, "PolicyKey must be 8-byte aligned");
    assert!(offset_of!(PolicyKey, cgroup_id) == 0);
    assert!(offset_of!(PolicyKey, family) == 8);
    assert!(offset_of!(PolicyKey, dst_ip) == 12);
    assert!(offset_of!(PolicyKey, dst_port) == 28);
};

#[repr(C)]
#[derive(Clone, Copy)]
pub struct PolicyValue {
    pub action: u8,
}

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
#[derive(Clone, Copy)]
pub struct SessionValue {
    pub session_id: [u8; 32],
    pub session_state: u32,
    pub expires_at: u64,
}

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

#[repr(C)]
#[derive(Clone, Copy)]
pub struct KernelFlowEvent {
    pub event_type: u32,
    pub decision: u32,
    pub pid: u32,
    pub tgid: u32,
    pub cgroup_id: u64,
    pub socket_cookie: u64,
    pub family: u32,
    pub protocol: u32,
    pub dst_addr: [u8; 16],
    pub dst_port: u16,
    pub action: u8,
    pub reason: u8,
}

const _: () = {
    use core::mem::{align_of, offset_of, size_of};
    assert!(
        size_of::<KernelFlowEvent>() == 64,
        "KernelFlowEvent must be 64 bytes"
    );
    assert!(
        align_of::<KernelFlowEvent>() == 8,
        "KernelFlowEvent must be 8-byte aligned"
    );
    assert!(offset_of!(KernelFlowEvent, event_type) == 0);
    assert!(offset_of!(KernelFlowEvent, decision) == 4);
    assert!(offset_of!(KernelFlowEvent, pid) == 8);
    assert!(offset_of!(KernelFlowEvent, tgid) == 12);
    assert!(offset_of!(KernelFlowEvent, cgroup_id) == 16);
    assert!(offset_of!(KernelFlowEvent, socket_cookie) == 24);
    assert!(offset_of!(KernelFlowEvent, family) == 32);
    assert!(offset_of!(KernelFlowEvent, protocol) == 36);
    assert!(offset_of!(KernelFlowEvent, dst_addr) == 40);
    assert!(offset_of!(KernelFlowEvent, dst_port) == 56);
    assert!(offset_of!(KernelFlowEvent, action) == 58);
    assert!(offset_of!(KernelFlowEvent, reason) == 59);
};
