// SPDX-License-Identifier: GPL-2.0
//
// Syntriass eBPF Policy Engine v2 — Phase 1: Policy Object Model.
//
// The Phase-3 scaffold (`policy.bpf.c`) drove egress from a single `u32`
// posture flag. This program replaces that flag with a *structured policy
// object* held in a BPF hash map, looked up per-flow by the kernel and
// distributed by userspace. Each cgroup (the unit a process group is confined
// to) carries one `struct syntriass_policy`; the `cgroup/connect4` hook resolves
// the calling task's cgroup, fetches its policy, and makes a fail-closed egress
// decision from the object's fields.
//
// Maps:
//   policy_table   HASH<u64 cgroup_id, struct syntriass_policy>  (userspace -> kernel)
//   session_state  HASH<u64 (daddr<<16|dport), u8>               (kernel -> userspace)
//   events         RINGBUF  one structured decision record       (kernel -> userspace)
//
// Fail-closed invariants (Phase-1 enforcement surface):
//   * map miss (no policy for this cgroup)      -> DENY  (REASON_NO_POLICY)
//   * policy present but expired                 -> DENY  (REASON_EXPIRED)
//   * posture == FailClosed                      -> DENY  (REASON_FAILCLOSED)
//   * otherwise (FullPqc / EncryptedFallback)    -> ALLOW, record session
// There is no posture value that yields plaintext: ALLOW only ever marks an
// encrypted session (FullPqc or EncryptedFallback); the overlay seals the bytes.

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define MODE_FULL_PQC 0u
#define MODE_ENCRYPTED_FALLBACK 1u
#define MODE_FAIL_CLOSED 2u

#define REASON_OK 0u
#define REASON_NO_POLICY 1u
#define REASON_EXPIRED 2u
#define REASON_FAILCLOSED 3u

// The structured policy object. Field order keeps the three u64s first so the
// 32-byte identity hash and the u32s stay naturally aligned; total 72 bytes.
struct syntriass_policy {
    __u64 policy_id;               // opaque unique id (userspace-assigned)
    __u64 cgroup_id;               // selector (informational; key duplicates it)
    __u64 expiry_ns;              // absolute bpf_ktime_get_ns(); 0 = never expires
    __u8 peer_identity_hash[32];  // SHA-256(peer identity); all-zero = any peer
    __u32 interface_id;           // ifindex this policy binds to; 0 = any
    __u32 posture;                // MODE_FULL_PQC / _ENCRYPTED_FALLBACK / _FAIL_CLOSED
    __u32 priority;               // higher wins on conflict (Phase 2 hierarchy)
    __u8 fallback_allowed;        // may degrade to EncryptedFallback (1) or not (0)
    __u8 audit_enabled;           // emit a ring-buffer audit record (1) or not (0)
    __u8 _pad[2];
};

// A structured audit/decision record (kernel -> userspace).
struct policy_event {
    __u64 policy_id;
    __u64 cgroup_id;
    __u32 pid;
    __u32 daddr;
    __u16 dport;
    __u16 posture;
    __u16 decision; // 0=allow 1=deny
    __u16 reason;   // REASON_*
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u64);
    __type(value, struct syntriass_policy);
} policy_table SEC(".maps");

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
int syntriass_policy_v2(struct bpf_sock_addr *ctx) {
    __u64 cgid = bpf_get_current_cgroup_id();
    struct syntriass_policy *pol = bpf_map_lookup_elem(&policy_table, &cgid);

    __u16 dport = bpf_ntohs(ctx->user_port);
    __u32 posture;
    __u16 reason;
    __u64 policy_id = 0;
    __u8 audit;

    if (!pol) {
        // No policy object for this cgroup => fail closed. Always audited so an
        // unconfigured cgroup's blocked egress is visible.
        posture = MODE_FAIL_CLOSED;
        reason = REASON_NO_POLICY;
        audit = 1;
    } else if (pol->expiry_ns != 0 && bpf_ktime_get_ns() > pol->expiry_ns) {
        // Expired credential => fail closed (a stale policy must not keep a
        // channel open). Audited regardless of the object's audit flag.
        posture = MODE_FAIL_CLOSED;
        reason = REASON_EXPIRED;
        policy_id = pol->policy_id;
        audit = 1;
    } else {
        posture = pol->posture;
        reason = (posture == MODE_FAIL_CLOSED) ? REASON_FAILCLOSED : REASON_OK;
        policy_id = pol->policy_id;
        audit = pol->audit_enabled;
    }

    __u16 decision = (posture == MODE_FAIL_CLOSED) ? 1 : 0; // 1 = deny (EPERM)

    if (decision == 0) {
        // ALLOW: mark the per-flow session (encrypted; 1=full-pqc, 2=fallback).
        __u64 fk = ((__u64)ctx->user_ip4 << 16) | dport;
        __u8 st = (__u8)(posture + 1);
        bpf_map_update_elem(&session_state, &fk, &st, BPF_ANY);
    }

    if (audit) {
        struct policy_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
        if (e) {
            __u64 id = bpf_get_current_pid_tgid();
            e->policy_id = policy_id;
            e->cgroup_id = cgid;
            e->pid = id >> 32;
            e->daddr = ctx->user_ip4;
            e->dport = dport;
            e->posture = (__u16)posture;
            e->decision = decision;
            e->reason = reason;
            bpf_ringbuf_submit(e, 0);
        }
    }

    return decision ? 0 : 1; // 0 = deny, 1 = allow
}

// Lookup-only variant: resolves the cgroup's policy object and makes the
// fail-closed decision (map miss / expired / FailClosed -> deny; else allow) with
// NO audit ring-buffer write and NO session marking. Attaching ONLY this program
// and bursting connects through it isolates the policy *lookup + decision* cost
// from the audit/telemetry cost (Phase 5), via the kernel's run-time accounting.
SEC("cgroup/connect4")
int syntriass_policy_lookup_bench(struct bpf_sock_addr *ctx) {
    (void)ctx;
    __u64 cgid = bpf_get_current_cgroup_id();
    struct syntriass_policy *pol = bpf_map_lookup_elem(&policy_table, &cgid);
    if (!pol) return 0; // map miss => fail closed
    if (pol->expiry_ns != 0 && bpf_ktime_get_ns() > pol->expiry_ns) return 0; // expired
    return (pol->posture == MODE_FAIL_CLOSED) ? 0 : 1;
}

char LICENSE[] SEC("license") = "GPL";
