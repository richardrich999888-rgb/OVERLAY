use aya_ebpf::{
    helpers::{bpf_get_current_cgroup_id, bpf_get_current_pid_tgid, bpf_ktime_get_ns},
    programs::SockAddrContext,
};

use crate::{
    audit::submit_audit,
    maps::{AF_INET, AF_INET6},
    types::{
        FlowKey, KernelFlowEvent, PendingFlow, PolicyKey, ACTION_ALLOW, ACTION_DENY,
        AUDIT_DECISION_ALLOW, AUDIT_DECISION_DENY, AUDIT_EVENT_CONNECT4, AUDIT_EVENT_CONNECT6,
        FLOW_STATE_PENDING, POLICY_ALLOW, POLICY_DENY, REASON_NO_POLICY, REASON_POLICY_ALLOW,
        REASON_POLICY_DENY, SESSION_PQC_ESTABLISHED,
    },
    AUDIT_RINGBUF, FLOW_PENDING_MAP, POLICY_MAP, SESSION_MAP,
};

pub const CGROUP_ALLOW: i32 = 1;
#[allow(dead_code)]
pub const CGROUP_DENY: i32 = 0;
const IPPROTO_TCP: u32 = 6;

pub fn handle_connect4(ctx: SockAddrContext) -> Result<i32, i64> {
    let raw = unsafe { &*ctx.sock_addr };
    if raw.protocol != IPPROTO_TCP {
        return Ok(CGROUP_ALLOW);
    }

    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid & 0xffff_ffff) as u32;
    let tgid = (pid_tgid >> 32) as u32;
    let cgroup_id = unsafe { bpf_get_current_cgroup_id() };

    let mut dst_addr = [0u8; 16];
    dst_addr[..4].copy_from_slice(&raw.user_ip4.to_be_bytes());
    let dst_port = (raw.user_port >> 16) as u16;
    let socket_cookie = socket_cookie_best_effort(&ctx);
    let mut policy_key = unsafe { core::mem::zeroed::<PolicyKey>() };
    policy_key.cgroup_id = cgroup_id;
    policy_key.family = AF_INET;
    policy_key.dst_ip = dst_addr;
    policy_key.dst_port = dst_port;

    let key = FlowKey {
        cgroup_id,
        pid,
        tgid,
        family: AF_INET,
        protocol: raw.protocol,
        dst_addr,
        dst_port,
        _pad: 0,
    };
    let pending = PendingFlow {
        first_seen_ns: unsafe { bpf_ktime_get_ns() },
        state: FLOW_STATE_PENDING,
        _pad: 0,
    };
    let _ = FLOW_PENDING_MAP.insert(&key, &pending, 0);

    match unsafe { POLICY_MAP.get(&policy_key) } {
        Some(v) if v.action == POLICY_ALLOW && session_established(socket_cookie) => {
            emit(
                AUDIT_EVENT_CONNECT4,
                AUDIT_DECISION_ALLOW,
                ACTION_ALLOW,
                REASON_POLICY_ALLOW,
                pid,
                tgid,
                cgroup_id,
                socket_cookie,
                AF_INET,
                raw.protocol,
                dst_addr,
                dst_port,
            )?;
            Ok(CGROUP_ALLOW)
        }
        Some(v) if v.action == POLICY_DENY => {
            emit(
                AUDIT_EVENT_CONNECT4,
                AUDIT_DECISION_DENY,
                ACTION_DENY,
                REASON_POLICY_DENY,
                pid,
                tgid,
                cgroup_id,
                socket_cookie,
                AF_INET,
                raw.protocol,
                dst_addr,
                dst_port,
            )?;
            Ok(CGROUP_DENY)
        }
        _ => {
            emit(
                AUDIT_EVENT_CONNECT4,
                AUDIT_DECISION_DENY,
                ACTION_DENY,
                REASON_NO_POLICY,
                pid,
                tgid,
                cgroup_id,
                socket_cookie,
                AF_INET,
                raw.protocol,
                dst_addr,
                dst_port,
            )?;
            Ok(CGROUP_DENY)
        }
    }
}

pub fn handle_connect6(ctx: SockAddrContext) -> Result<i32, i64> {
    let raw = unsafe { &*ctx.sock_addr };
    if raw.protocol != IPPROTO_TCP {
        return Ok(CGROUP_ALLOW);
    }

    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid & 0xffff_ffff) as u32;
    let tgid = (pid_tgid >> 32) as u32;
    let cgroup_id = unsafe { bpf_get_current_cgroup_id() };

    let mut dst_addr = [0u8; 16];
    for (i, word) in raw.user_ip6.iter().enumerate() {
        dst_addr[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    let dst_port = (raw.user_port >> 16) as u16;
    let socket_cookie = socket_cookie_best_effort(&ctx);
    let mut policy_key = unsafe { core::mem::zeroed::<PolicyKey>() };
    policy_key.cgroup_id = cgroup_id;
    policy_key.family = AF_INET6;
    policy_key.dst_ip = dst_addr;
    policy_key.dst_port = dst_port;

    let key = FlowKey {
        cgroup_id,
        pid,
        tgid,
        family: AF_INET6,
        protocol: raw.protocol,
        dst_addr,
        dst_port,
        _pad: 0,
    };
    let pending = PendingFlow {
        first_seen_ns: unsafe { bpf_ktime_get_ns() },
        state: FLOW_STATE_PENDING,
        _pad: 0,
    };
    let _ = FLOW_PENDING_MAP.insert(&key, &pending, 0);

    match unsafe { POLICY_MAP.get(&policy_key) } {
        Some(v) if v.action == POLICY_ALLOW && session_established(socket_cookie) => {
            emit(
                AUDIT_EVENT_CONNECT6,
                AUDIT_DECISION_ALLOW,
                ACTION_ALLOW,
                REASON_POLICY_ALLOW,
                pid,
                tgid,
                cgroup_id,
                socket_cookie,
                AF_INET6,
                raw.protocol,
                dst_addr,
                dst_port,
            )?;
            Ok(CGROUP_ALLOW)
        }
        Some(v) if v.action == POLICY_DENY => {
            emit(
                AUDIT_EVENT_CONNECT6,
                AUDIT_DECISION_DENY,
                ACTION_DENY,
                REASON_POLICY_DENY,
                pid,
                tgid,
                cgroup_id,
                socket_cookie,
                AF_INET6,
                raw.protocol,
                dst_addr,
                dst_port,
            )?;
            Ok(CGROUP_DENY)
        }
        _ => {
            emit(
                AUDIT_EVENT_CONNECT6,
                AUDIT_DECISION_DENY,
                ACTION_DENY,
                REASON_NO_POLICY,
                pid,
                tgid,
                cgroup_id,
                socket_cookie,
                AF_INET6,
                raw.protocol,
                dst_addr,
                dst_port,
            )?;
            Ok(CGROUP_DENY)
        }
    }
}

fn session_established(socket_cookie: u64) -> bool {
    if socket_cookie == 0 {
        return false;
    }
    let now = unsafe { bpf_ktime_get_ns() };
    match unsafe { SESSION_MAP.get(&socket_cookie) } {
        Some(session) => {
            session.session_state == SESSION_PQC_ESTABLISHED && session.expires_at > now
        }
        None => false,
    }
}

#[allow(clippy::too_many_arguments)]
fn emit(
    event_type: u32,
    decision: u32,
    action: u8,
    reason: u8,
    pid: u32,
    tgid: u32,
    cgroup_id: u64,
    socket_cookie: u64,
    family: u32,
    protocol: u32,
    dst_addr: [u8; 16],
    dst_port: u16,
) -> Result<(), i64> {
    submit_audit(
        &AUDIT_RINGBUF,
        KernelFlowEvent {
            event_type,
            decision,
            pid,
            tgid,
            cgroup_id,
            socket_cookie,
            family,
            protocol,
            dst_addr,
            dst_port,
            action,
            reason,
        },
    )
}

fn socket_cookie_best_effort(ctx: &SockAddrContext) -> u64 {
    let raw = unsafe { &*ctx.sock_addr };
    let sk = unsafe { raw.__bindgen_anon_1.sk };
    if sk.is_null() {
        0
    } else {
        unsafe { aya_ebpf::helpers::bpf_get_socket_cookie(sk as *mut _) }
    }
}
