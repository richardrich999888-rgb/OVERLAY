#![no_std]
#![no_main]

//! Aya eBPF `sockops` program for Syntriass kernel-native enforcement.
//!
//! OUT OF TREE: this crate is intentionally outside the default Cargo workspace
//! and is **not** built by `cargo check`/`cargo test`. It compiles only with the
//! eBPF toolchain (nightly + `bpf-linker`, `cargo +nightly build --target
//! bpfel-unknown-none -Z build-std=core`) and loads only with CAP_BPF on a kernel
//! with `CONFIG_BPF_SYSCALL` + sockops + RingBuf support.
//!
//! On an established connection it captures the 4-tuple, family, cgroup id and
//! socket cookie, and streams a [`SockEvent`] into the `EVENTS` RingBuf. The
//! user-space daemon consumes those records (`KernelSockEvent::from_bytes`),
//! runs the hybrid PQC handshake, and installs kTLS keys back onto the socket.

use aya_ebpf::{
    bindings::{BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB, BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB},
    helpers::{bpf_get_current_cgroup_id, bpf_get_socket_cookie},
    macros::{cgroup_sock_addr, map, sock_ops},
    maps::{Array, HashMap, RingBuf},
    programs::{SockAddrContext, SockOpsContext},
};

mod audit;
mod cgroup_connect;
mod maps;
mod types;
use maps::{KernelCounters, SockEvent, AF_INET, AF_INET6};
use types::{FlowKey, IdentityRecord, PendingFlow, PolicyKey, PolicyValue, SessionValue};

/// 256 KiB lock-free ring buffer for connection upcalls.
#[map(name = "EVENTS")]
static EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

/// Phase 1 audit ring buffer for cgroup/connect visibility.
#[map(name = "AUDIT_RINGBUF")]
pub static AUDIT_RINGBUF: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

/// Phase 1 flow inventory keyed by cgroup/process/destination tuple.
#[map(name = "FLOW_PENDING_MAP")]
pub static FLOW_PENDING_MAP: HashMap<FlowKey, PendingFlow> = HashMap::with_max_entries(65_536, 0);

/// Workload identity cache populated by user space in later phases. Present in
/// Phase 1 so the ABI and pinning surface is stable before enforcement begins.
#[map(name = "IDENTITY_MAP")]
pub static IDENTITY_MAP: HashMap<u64, IdentityRecord> = HashMap::with_max_entries(16_384, 0);

/// Phase 2 deny-by-default egress policy map. Pinned so `syntriassctl` can
/// update it without reloading the eBPF programs.
#[map(name = "POLICY_MAP")]
pub static POLICY_MAP: HashMap<PolicyKey, PolicyValue> = HashMap::pinned(65_536, 0);

/// Phase 3 transport-binding state. A policy allow is insufficient unless the
/// socket cookie has an established, unexpired PQC session here.
#[map(name = "SESSION_MAP")]
pub static SESSION_MAP: HashMap<u64, SessionValue> = HashMap::pinned(65_536, 0);

#[map(name = "KERNEL_COUNTERS")]
static KERNEL_COUNTERS: Array<KernelCounters> = Array::with_max_entries(1, 0);

#[cgroup_sock_addr(connect4)]
pub fn syntriass_connect4(ctx: SockAddrContext) -> i32 {
    match cgroup_connect::handle_connect4(ctx) {
        Ok(action) => action,
        Err(_) => cgroup_connect::CGROUP_DENY,
    }
}

#[cgroup_sock_addr(connect6)]
pub fn syntriass_connect6(ctx: SockAddrContext) -> i32 {
    match cgroup_connect::handle_connect6(ctx) {
        Ok(action) => action,
        Err(_) => cgroup_connect::CGROUP_DENY,
    }
}

#[sock_ops]
pub fn syntriass_sock_handler(ctx: SockOpsContext) -> u32 {
    match try_handle(&ctx) {
        Ok(action) => action,
        Err(_) => 0,
    }
}

fn try_handle(ctx: &SockOpsContext) -> Result<u32, i64> {
    let op = ctx.op();
    if op != BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB && op != BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB {
        return Ok(0);
    }

    // `ctx` ports are host-order u32 in the sockops view; addresses are __be32.
    let local_port = ctx.local_port() as u16;
    let remote_port = (ctx.remote_port() >> 16) as u16; // remote_port is in network order, high half
    if local_port == 0 || remote_port == 0 {
        return Ok(0);
    }

    let family = ctx.family();
    let mut src_addr = [0u8; 16];
    let mut dst_addr = [0u8; 16];
    if family == AF_INET6 {
        copy_ip6(ctx.local_ip6(), &mut src_addr);
        copy_ip6(ctx.remote_ip6(), &mut dst_addr);
    } else {
        // __be32 addresses: store the 4 network-order bytes in the first 4 slots.
        src_addr[..4].copy_from_slice(&ctx.local_ip4().to_be_bytes());
        dst_addr[..4].copy_from_slice(&ctx.remote_ip4().to_be_bytes());
    }

    let event = SockEvent {
        cookie: unsafe { bpf_get_socket_cookie(ctx.ops as *mut _) },
        cgroup_id: unsafe { bpf_get_current_cgroup_id() },
        src_addr,
        dst_addr,
        src_port: local_port,
        dst_port: remote_port,
        family: if family == AF_INET6 {
            AF_INET6 as u16
        } else {
            AF_INET as u16
        },
        _pad: 0,
    };

    submit(event)?;
    bump_upcalls();
    Ok(1)
}

/// Copy an IPv6 address (4 __be32 words) into a 16-byte buffer.
fn copy_ip6(words: [u32; 4], out: &mut [u8; 16]) {
    for (i, w) in words.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&w.to_be_bytes());
    }
}

/// Reserve + write + submit one event into the RingBuf (lock-free upcall).
fn submit(event: SockEvent) -> Result<(), i64> {
    match EVENTS.reserve::<SockEvent>(0) {
        Some(mut entry) => {
            entry.write(event);
            entry.submit(0);
            Ok(())
        }
        None => {
            bump_failures();
            Err(-1)
        }
    }
}

fn bump_upcalls() {
    if let Some(c) = KERNEL_COUNTERS.get_ptr_mut(0) {
        unsafe { (*c).upcalls += 1 }
    }
}

fn bump_failures() {
    if let Some(c) = KERNEL_COUNTERS.get_ptr_mut(0) {
        unsafe { (*c).failures += 1 }
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
