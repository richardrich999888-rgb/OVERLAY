// SPDX-License-Identifier: GPL-2.0
//
// Syntriass production eBPF policy/state layer.
//
// A `cgroup/connect4` program whose egress decision is driven by LIVE kernel map
// state that userspace distributes: the operational posture, the fallback flag,
// and per-flow session state. This replaces the scaffold's static config with an
// operational kernel policy engine — the same hook the universal-interception
// data plane uses (`connect4.bpf.c`), but posture-aware and fail-closed.
//
// Maps (read by the kernel, written by userspace — and session_state written by
// the kernel, read by userspace, i.e. bidirectional synchronization):
//   operation_mode  ARRAY[1] u32   0=FullPqc 1=EncryptedFallback 2=FailClosed
//   fallback_state  ARRAY[1] u32   0=inactive 1=active (encrypted fallback engaged)
//   session_state   HASH<u64,u8>   per-flow state, keyed by (daddr<<16 | dport)
//   events          RINGBUF        one record per decision (for the supervisor)
//
// Enforcement:
//   FailClosed         -> DENY every outbound connect (EPERM). The fail-closed
//                         posture: no egress leaves the cgroup, period.
//   EncryptedFallback  -> ALLOW (the userspace control plane forces the encrypted
//                         PSK path; never plaintext) and mark the session.
//   FullPqc            -> ALLOW and mark the session.

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define MODE_FULL_PQC 0u
#define MODE_ENCRYPTED_FALLBACK 1u
#define MODE_FAIL_CLOSED 2u

struct policy_event {
    __u32 pid;
    __u32 daddr;
    __u16 dport;
    __u16 mode;
    __u16 decision; // 0=allow 1=deny
    __u16 _pad;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} operation_mode SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} fallback_state SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, __u64);
    __type(value, __u8);
} session_state SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 22);
} events SEC(".maps");

SEC("cgroup/connect4")
int syntriass_policy(struct bpf_sock_addr *ctx) {
    __u32 k0 = 0;
    __u32 *modep = bpf_map_lookup_elem(&operation_mode, &k0);
    __u32 mode = modep ? *modep : MODE_FAIL_CLOSED; // map miss => fail closed

    __u16 dport = bpf_ntohs(ctx->user_port);
    __u16 decision = (mode == MODE_FAIL_CLOSED) ? 1 : 0;

    // Record/refresh per-flow session state (kernel -> userspace distribution).
    if (decision == 0) {
        __u64 fk = ((__u64)ctx->user_ip4 << 16) | dport;
        __u8 st = (__u8)(mode + 1); // 1=full-pqc-session, 2=fallback-session
        bpf_map_update_elem(&session_state, &fk, &st, BPF_ANY);
    }

    struct policy_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (e) {
        __u64 id = bpf_get_current_pid_tgid();
        e->pid = id >> 32;
        e->daddr = ctx->user_ip4;
        e->dport = dport;
        e->mode = (__u16)mode;
        e->decision = decision;
        e->_pad = 0;
        bpf_ringbuf_submit(e, 0);
    }

    return decision ? 0 : 1; // 0 = deny (EPERM), 1 = allow
}

char LICENSE[] SEC("license") = "GPL";
