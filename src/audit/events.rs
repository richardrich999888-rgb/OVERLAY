use serde::{Deserialize, Serialize};
use std::net::{Ipv4Addr, Ipv6Addr};

pub const AUDIT_EVENT_CONNECT4: u32 = 1;
pub const AUDIT_EVENT_CONNECT6: u32 = 2;
pub const AUDIT_DECISION_ALLOW: u32 = 1;
pub const AUDIT_DECISION_DENY: u32 = 2;
pub const ACTION_ALLOW: u8 = 1;
pub const ACTION_DENY: u8 = 2;
pub const REASON_POLICY_ALLOW: u8 = 1;
pub const REASON_POLICY_DENY: u8 = 2;
pub const REASON_NO_POLICY: u8 = 3;

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

impl KernelFlowEvent {
    pub const WIRE_LEN: usize = core::mem::size_of::<KernelFlowEvent>();

    pub fn from_bytes(buf: &[u8]) -> Option<Self> {
        if buf.len() < Self::WIRE_LEN {
            return None;
        }
        let rd_u32 = |o: usize| u32::from_ne_bytes(buf[o..o + 4].try_into().unwrap());
        let rd_u64 = |o: usize| u64::from_ne_bytes(buf[o..o + 8].try_into().unwrap());
        let rd_u16 = |o: usize| u16::from_ne_bytes(buf[o..o + 2].try_into().unwrap());
        let mut dst_addr = [0u8; 16];
        dst_addr.copy_from_slice(&buf[40..56]);
        Some(Self {
            event_type: rd_u32(0),
            decision: rd_u32(4),
            pid: rd_u32(8),
            tgid: rd_u32(12),
            cgroup_id: rd_u64(16),
            socket_cookie: rd_u64(24),
            family: rd_u32(32),
            protocol: rd_u32(36),
            dst_addr,
            dst_port: rd_u16(56),
            action: buf[58],
            reason: buf[59],
        })
    }

    pub fn destination(&self) -> String {
        match self.family {
            10 => Ipv6Addr::from(self.dst_addr).to_string(),
            _ => Ipv4Addr::new(
                self.dst_addr[0],
                self.dst_addr[1],
                self.dst_addr[2],
                self.dst_addr[3],
            )
            .to_string(),
        }
    }

    pub fn event_name(&self) -> &'static str {
        match self.event_type {
            AUDIT_EVENT_CONNECT4 => "connect4",
            AUDIT_EVENT_CONNECT6 => "connect6",
            _ => "unknown",
        }
    }

    pub fn decision_name(&self) -> &'static str {
        match self.decision {
            AUDIT_DECISION_ALLOW => "allow",
            AUDIT_DECISION_DENY => "deny",
            _ => "unknown",
        }
    }

    pub fn to_audit_record(&self) -> FlowAuditRecord {
        FlowAuditRecord {
            event: self.event_name(),
            decision: self.decision_name(),
            action: self.action_name(),
            reason: self.reason_name(),
            pid: self.pid,
            tgid: self.tgid,
            cgroup_id: self.cgroup_id,
            socket_cookie: self.socket_cookie,
            family: self.family,
            protocol: self.protocol,
            destination_ip: self.destination(),
            destination_port: self.dst_port,
        }
    }

    pub fn action_name(&self) -> &'static str {
        match self.action {
            ACTION_ALLOW => "allow",
            ACTION_DENY => "deny",
            _ => "unknown",
        }
    }

    pub fn reason_name(&self) -> &'static str {
        match self.reason {
            REASON_POLICY_ALLOW => "policy_allow",
            REASON_POLICY_DENY => "policy_deny",
            REASON_NO_POLICY => "no_policy",
            _ => "unknown",
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct FlowAuditRecord {
    pub event: &'static str,
    pub decision: &'static str,
    pub action: &'static str,
    pub reason: &'static str,
    pub pid: u32,
    pub tgid: u32,
    pub cgroup_id: u64,
    pub socket_cookie: u64,
    pub family: u32,
    pub protocol: u32,
    pub destination_ip: String,
    pub destination_port: u16,
}
