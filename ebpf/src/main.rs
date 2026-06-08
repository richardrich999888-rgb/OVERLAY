#![no_std]
#![no_main]

//! Conceptual Aya eBPF sockops program for Syntriass kernel-native enforcement.
//!
//! This source is intentionally outside the default Cargo package. It is meant
//! to be compiled with an eBPF target once an aya-bpf workspace and loader are
//! added. The user-space daemon in `src/bin/daemon.rs` owns the heavy PQC work.

use aya_bpf::{
    bindings::{
        BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB, BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB,
    },
    macros::{map, sock_ops},
    maps::{Array, SockMap},
    programs::SockOpsContext,
};

mod maps;
use maps::{KernelCounters, SecureSocket, SOCKET_FLAG_PQC_REQUIRED};

#[map(name = "SECURE_SOCKETS")]
static mut SECURE_SOCKETS: SockMap = SockMap::with_max_entries(65535, 0);

#[map(name = "KERNEL_COUNTERS")]
static mut KERNEL_COUNTERS: Array<KernelCounters> = Array::with_max_entries(1, 0);

#[sock_ops(name = "syntriass_sock_handler")]
pub fn syntriass_sock_handler(ctx: SockOpsContext) -> u32 {
    match try_syntriass_sock_handler(ctx) {
        Ok(action) => action,
        Err(_) => 0,
    }
}

fn try_syntriass_sock_handler(ctx: SockOpsContext) -> Result<u32, i64> {
    let op = ctx.op();
    if op != BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB && op != BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB {
        return Ok(0);
    }

    let local_port = ctx.local_port();
    let remote_port = ctx.remote_port();
    if !must_enforce_pqc(local_port, remote_port) {
        return Ok(0);
    }

    let socket = SecureSocket {
        socket_id: socket_cookie(&ctx),
        local_port,
        remote_port,
        cgroup_id: cgroup_id(&ctx),
        flags: SOCKET_FLAG_PQC_REQUIRED,
    };

    publish_upcall(socket)?;
    Ok(1)
}

fn must_enforce_pqc(local_port: u16, remote_port: u16) -> bool {
    local_port != 0 && remote_port != 0
}

fn socket_cookie(_ctx: &SockOpsContext) -> u64 {
    0
}

fn cgroup_id(_ctx: &SockOpsContext) -> u64 {
    0
}

fn publish_upcall(_socket: SecureSocket) -> Result<(), i64> {
    unsafe {
        if let Some(counters) = KERNEL_COUNTERS.get_ptr_mut(0) {
            (*counters).upcalls += 1;
        }
    }
    Ok(())
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
