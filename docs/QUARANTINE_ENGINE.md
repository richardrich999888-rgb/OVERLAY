# Quarantine Engine — eBPF Policy Engine v2, Phase 4

Tags: **[measured]** real kernel run · **[tested]** automated assertion ·
**[implemented]** code exists.

**Objective:** isolate a compromised or flagged confinement unit by denying **all**
its egress — the highest-priority deny, overriding every policy level — with three
quarantine kinds and correct recovery:

| Kind | Releases when | Use |
|---|---|---|
| **Temporary** | the configured duration elapses (auto) | cool-off after a transient security event |
| **AutoExpiry** | an absolute deadline passes (auto) | "isolated until 14:00" / credential-bound |
| **Permanent** | a manual release (delete) — never automatically | confirmed compromise; hold until cleared |

All numbers measured on this host (kernel **6.18.5**) by
`scripts/ebpf_quarantine_validate.sh`. Each step is a **real** `connect` through
the live `cgroup/connect4` hook. No fabricated data.

---

## 1. Implementation — **[implemented]** (`ebpf/c/policy_v2.bpf.c`)

A `quarantine` BPF hash keyed by cgroup id holds:

```c
struct quarantine_entry {
    __u64 quarantine_id; // audit correlation
    __u64 expiry_ns;     // absolute bpf_ktime_get_ns(); 0 = no expiry (Permanent)
    __u32 kind;          // QUAR_TEMPORARY / QUAR_PERMANENT / QUAR_AUTO_EXPIRY
    __u32 _qpad;
};
```

The hook checks quarantine **first**, before any policy resolution:

```c
static __always_inline int syntriass_quarantined(__u64 cgid) {
    struct quarantine_entry *q = bpf_map_lookup_elem(&quarantine, &cgid);
    if (!q) return 0;
    if (q->kind == QUAR_PERMANENT) return 1;               // never auto-releases
    return (q->expiry_ns != 0 && bpf_ktime_get_ns() <= q->expiry_ns); // auto-release at deadline
}
```

If quarantined, the hook denies (`EPERM`) with `REASON_QUARANTINE` and emits a
structured audit record — **regardless of any Global/Node/App/Session policy**.
Quarantine is therefore strictly dominant over the Phase-2 hierarchy and the
Phase-3 crypto gate; nothing a policy says can re-open a quarantined cgroup.

`Temporary` and `AutoExpiry` are both deadline-compared in the kernel (they differ
operationally in how userspace computes the deadline — a duration vs an absolute
time — and in which control-plane component garbage-collects the expired entry);
`Permanent` ignores the deadline and holds until the entry is deleted.

---

## 2. Correctness & recovery — **[tested]** (4/4)

| Check | t≈200 ms | t≈900 ms | Recovery |
|---|---|---|---|
| **Temporary** (500 ms, no manual release) | DENY (EPERM) | **ALLOW** | auto-released at the duration |
| **AutoExpiry** (500 ms deadline) | DENY (EPERM) | **ALLOW** | auto-released at the deadline |
| **Permanent** (manual release @600 ms) | DENY (EPERM) | **ALLOW** | released only by the manual delete |
| **Permanent, no release** | DENY | DENY | **stays denied** — no auto-recovery |

The last row is the discriminator: a Permanent quarantine with no manual release
stays denied for the whole run — proving Permanent does **not** auto-recover, while
Temporary/AutoExpiry do. Every denied connect carries `reason=quarantine` in the
kernel audit stream.

---

## 3. Measured results — **[measured]**

`scripts/ebpf_quarantine_validate.sh`, kernel 6.18.5:

| Metric | Value | How |
|---|---:|---|
| **quarantine propagation** (userspace push → enforced) | **2 µs**, live on the next connect | `bpf_map_update_elem(quarantine)` |
| **quarantine enforcement latency** (check + deny) | **325 ns / connect** | lookup-only program with an active quarantine, 50 000 real connects, kernel run-time accounting |
| **recovery — auto** (Temporary / AutoExpiry) | = configured duration (here 500 ms); post-deadline **enforcement is immediate** (sub-µs, ktime compared per connect) | real connects before/after the deadline |
| **recovery — manual** (Permanent) | release delete **15 µs**, enforced on the next connect | timed `bpf_map_delete_elem` |
| correctness | **4/4 checks** | real connects, `reason=quarantine` verified |

Note the enforcement latency (**325 ns**) is *lower* than the full 4-level resolve
(~895 ns, Phase 2): an active quarantine **short-circuits** policy resolution — the
cheapest possible path is the one that denies a compromised cgroup.

---

## 4. Success criteria — status

| Criterion (mission) | Status |
|---|---|
| QuarantinePolicy Temporary / Permanent / Auto-Expiry | ✅ [implemented] three kinds; auto vs manual release |
| Quarantine propagation latency | ✅ [measured] 2 µs push, live on the next connect |
| Quarantine enforcement latency | ✅ [measured] 325 ns / connect (check + deny) |
| Quarantine recovery latency | ✅ [measured] auto = configured duration (immediate post-deadline enforcement); manual = 15 µs delete + next connect |
| Correctness | ✅ [tested] 4/4 (incl. Permanent does not auto-recover) |

---

## 5. Residual risks & limitations

- **Quarantine is keyed by cgroup id.** Per-peer or per-flow quarantine (isolate a
  specific compromised peer rather than a whole confinement unit) needs the
  identity-to-flow binding from the OOB layer (shared residual with Phase 2's
  Session keying). **[design]**.
- **Auto-release relies on the kernel clock comparison**, not on a timer that
  actively wakes; an expired entry lingers in the map (consuming a slot) until the
  control plane garbage-collects it. Enforcement is correct throughout (an expired
  entry reads as inactive), but a userspace sweep should reclaim expired
  Temporary/AutoExpiry entries — a small control-plane task, **[design]**.
- **The quarantine producer** (what decides to quarantine, e.g. the kinetic
  `Supervisor` on a `SecurityViolation`, `src/kinetic.rs`) is not yet wired to push
  into this map in the live daemon — the same deferred daemon-integration plumbing
  noted in earlier phases. The mechanism, kinds, propagation, enforcement, and
  recovery are all measured here.

## 6. Readiness impact

The platform can now isolate a compromised confinement unit in the kernel in
**2 µs**, deny its egress in **325 ns/connect** overriding all policy, and recover
it deterministically (auto at the deadline, or manual-only for Permanent). This is
the containment primitive a defence operator needs when a node is suspected
compromised. See `docs/DEFENCE_READINESS_REVIEW.md` row **EBPF-P4**.
