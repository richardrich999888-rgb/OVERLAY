// SPDX-License-Identifier: GPL-2.0
//
// Syntriass universal-interception data plane: a `cgroup/connect4` eBPF program.
//
// This is the kernel-level replacement for LD_PRELOAD libc interposition. It runs
// inside the kernel's `connect(2)` path (`__cgroup_bpf_run_filter_sock_addr`),
// so it observes — and can enforce on — EVERY outbound IPv4 connection made by any
// process in the attached cgroup, regardless of how that process issued the call:
// glibc, musl, a fully static binary, Go's runtime (which bypasses libc), a raw
// `syscall(SYS_connect, ...)`, etc. LD_PRELOAD sees none of the no-libc cases;
// this hook sees all of them.
//
// Two responsibilities:
//   1. Observation: every connect is recorded into a ring buffer (the control
//      daemon consumes these to drive the PQC handshake — the same
//      `KernelSockEvent` contract the userspace side already speaks).
//   2. Enforcement (fail-closed): if `config[0]` is a non-zero destination port,
//      a connect to that port is DENIED (returns 0 -> the syscall fails with
//      EPERM). This is the primitive a policy layer uses to force traffic through
//      the overlay (deny direct egress; allow only the proxied path).
//
// Built out-of-tree with clang (`ebpf/c/build.sh`); loaded with libbpf
// (`ebpf/c/loader.c`). Validated on this host by
// `scripts/ebpf_coverage_validate.sh`.

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// One connection event. Field order/sizes are deliberate and documented in
// ebpf/README.md; the userspace consumer reads the same layout.
struct conn_event {
    __u32 pid;
    __u32 uid;
    __u32 daddr;   // destination IPv4, network byte order
    __u16 dport;   // destination port, host byte order
    __u16 action;  // 0 = allowed, 1 = denied (enforcement)
    char comm[16];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24); // 16 MiB
} events SEC(".maps");

// Enforcement policy, set by the loader after load. config[0] = blocked dest
// port in host byte order (0 disables enforcement; observe-only).
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u16);
} config SEC(".maps");

SEC("cgroup/connect4")
int syntriass_connect4(struct bpf_sock_addr *ctx) {
    __u16 dport = bpf_ntohs(ctx->user_port);

    __u32 k = 0;
    __u16 *blocked = bpf_map_lookup_elem(&config, &k);
    __u16 action = 0;
    if (blocked && *blocked != 0 && dport == *blocked)
        action = 1; // deny

    struct conn_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (e) {
        __u64 id = bpf_get_current_pid_tgid();
        e->pid = id >> 32;
        e->uid = (__u32)bpf_get_current_uid_gid();
        e->daddr = ctx->user_ip4;
        e->dport = dport;
        e->action = action;
        bpf_get_current_comm(&e->comm, sizeof(e->comm));
        bpf_ringbuf_submit(e, 0);
    }

    return action ? 0 : 1; // 0 = deny (EPERM), 1 = allow
}

char LICENSE[] SEC("license") = "GPL";
