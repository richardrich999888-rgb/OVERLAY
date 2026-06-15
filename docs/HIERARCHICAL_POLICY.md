# Hierarchical Policy Engine — eBPF Policy Engine v2, Phase 2

Tags: **[measured]** real kernel run · **[tested]** automated assertion ·
**[implemented]** code exists.

**Objective:** resolve an *effective* policy by inheritance across four levels —
**Global → Node → Application → Session** — with conflict resolution =
**Highest Priority Wins** (ties break toward the more specific level), enforced
fail-closed in the kernel on every `connect`.

All numbers are measured on this host (kernel **6.18.5**, clang 18, libbpf,
cgroup v2, root) by `scripts/ebpf_policy_hier_validate.sh`. No fabricated data.

---

## 1. The hierarchy — **[implemented]** (`ebpf/c/policy_v2.bpf.c`)

Each level is a BPF map of `struct syntriass_policy` (the Phase-1 object,
`docs/POLICY_OBJECT_MODEL.md`):

| Level | Map | Key | Scope |
|---|---|---|---|
| Global | `global_policy` `ARRAY[1]` | `0` | the whole node, every flow |
| Node | `node_policy` `ARRAY[1]` | `0` | this node's baseline |
| Application | `policy_table` `HASH` | `u64 cgroup_id` | a confinement unit (pod/service) |
| Session | `session_policy` `HASH` | `u64 (daddr<<16\|dport)` | a specific flow |

The `cgroup/connect4` hook resolves all four for the calling flow and selects the
effective policy. ARRAY levels always have index 0 present, so an *absent* Global
or Node policy is encoded by a zeroed object (`policy_id == 0` ⇒ ignored); absent
Application/Session policies are ordinary map misses.

### Resolution — Highest Priority Wins, specificity breaks ties

```c
static __always_inline struct syntriass_policy *
syntriass_resolve(__u64 cgid, __u64 flowkey, __u32 *out_level) {
    __u64 now = bpf_ktime_get_ns();
    struct syntriass_policy *best = 0; long long best_prio = -1;
    __u32 best_level = LEVEL_GLOBAL;
    CONSIDER(global_policy[0],        LEVEL_GLOBAL);   // least specific first ...
    CONSIDER(node_policy[0],          LEVEL_NODE);
    CONSIDER(policy_table[cgid],      LEVEL_APP);
    CONSIDER(session_policy[flowkey], LEVEL_SESSION);  // ... most specific last
    *out_level = best_level; return best;             // NULL => fail closed
}
```

`CONSIDER` ignores a candidate that is absent (`policy_id == 0`) or **expired**
(`expiry_ns` in the past), and keeps the highest priority seen; because it runs
least- to most-specific and compares with `>=`, an equal-priority tie resolves to
the more specific level. If no level yields an applicable policy, resolution
returns `NULL` and the hook fails closed (`REASON_NO_POLICY`). The same fail-closed
decision rules as Phase 1 then apply to the winner (FailClosed posture ⇒ deny;
FullPqc/EncryptedFallback ⇒ allow; no posture expresses plaintext).

---

## 2. Correctness — **[tested]** (6/6, each a real connect)

Every scenario sets the level maps from userspace, then drives a **real**
`connect()` through the live hook; the decision **and the winning level** are read
back from the kernel ring buffer.

| # | Scenario | Levels (posture@priority) | Winner | Decision | Proves |
|---|---|---|---|---|---|
| 1 | inherit_global | G:FullPqc@10 | **global** | ALLOW (errno 111) | inheritance down from Global |
| 2 | app_overrides_global | G:FullPqc@10, A:FailClosed@100 | **app** | DENY (EPERM) | higher-priority App overrides Global |
| 3 | global_highest_wins | G:FailClosed@100, A:FullPqc@10 | **global** | DENY (EPERM) | **highest priority beats more-specific** |
| 4 | tie_breaks_to_specific | G@50, N@50, A:FailClosed@50 | **app** | DENY (EPERM) | equal priority ⇒ most specific wins |
| 5 | session_highest | A:FailClosed@50, S:FullPqc@200 | **session** | ALLOW (errno 111) | Session level, highest priority |
| 6 | all_expired_failclosed | all expired | — | DENY (EPERM) | no applicable level ⇒ **fail closed** |

Scenario 3 is the key discriminator: it proves the engine implements *Highest
Priority Wins* and not mere specificity — a high-priority Global FailClosed beats a
low-priority, more-specific Application FullPqc, and the connection is denied.

---

## 3. Measured results — **[measured]**

`scripts/ebpf_policy_hier_validate.sh`, kernel 6.18.5:

| Metric | Value | How |
|---|---:|---|
| **inheritance resolution latency** (4-level resolve + decision) | **895 ns / connect** | lookup-only hierarchical program with all four levels populated, 50 000 real connects, kernel run-time accounting |
| single-level lookup (Phase 1, for comparison) | 343 ns / connect | one map lookup |
| **update propagation** (userspace push → enforced) | **1–2 µs**, live on the **next connect** | `bpf_map_update_elem` at any level; the kernel reads live map state per packet |
| resolution correctness | **6/6 scenarios** | real connects, winning level verified |

The four-level resolution costs ~550 ns more than a single lookup — three
additional BPF hash/array lookups plus the priority comparison — and stays well
under a microsecond. Propagation is effectively instantaneous: there is no
recompile, reload, or cache-flush step; a pushed object is consulted by the very
next packet's hook invocation.

---

## 4. Success criteria — status

| Criterion (mission) | Status |
|---|---|
| Policy inheritance Global→Node→Application→Session | ✅ [tested] four-level resolver; scenarios 1/5 show inheritance, 2/4 show override |
| Conflict resolution = Highest Priority Wins | ✅ [tested] scenario 3 (priority beats specificity) + scenario 4 (specificity breaks ties) |
| Inheritance resolution latency measured | ✅ [measured] 895 ns / connect (§3) |
| Update propagation measured | ✅ [measured] 1–2 µs push, enforced on the next connect (§3) |
| Correctness | ✅ [tested] 6/6 scenarios, winning level verified from the kernel |

---

## 5. Residual risks & limitations

- **Session keying is flow-tuple (daddr,dport)**, not peer-identity, at this
  phase — the socket address is all the `connect4` hook has. Per-peer Session
  policy keyed by `peer_identity_hash` requires associating an identity with the
  flow (the OOB identity layer, `src/crypto/oob.rs`), wired in a later phase.
  **[design]** until then; the object already carries the field.
- **Levels are evaluated unconditionally (4 lookups/connect)** even when upper
  levels are absent. The cost is measured (895 ns) and acceptable; a short-circuit
  optimization is possible but unnecessary at this latency.
- **cgroup-id stability** (Phase-1 residual) still applies to the Application
  level: a cgroup delete/recreate needs a re-push.
- **Priority is operator-assigned**; a misconfigured low-priority Global FailClosed
  could be overridden by a high-priority Application FullPqc. This is by design
  (Highest Priority Wins), so priority ranges are a deployment-profile concern —
  addressed in Phase 6 (Defence Policy Profiles), which pins profile priorities.

## 6. Readiness impact

Policy is now hierarchical and composable: a node-wide baseline, per-application
overrides, and per-flow exceptions resolve to a single effective decision in
**895 ns** in the kernel, fail-closed when nothing applies. See
`docs/DEFENCE_READINESS_REVIEW.md` row **EBPF-P2**.
