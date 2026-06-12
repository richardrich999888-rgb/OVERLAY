# Defence Deployment Scenario — Phase 3

Tags: **[measured]** real run · **[tested]** automated assertion ·
**[implemented]** code exists · **[design]** needs external infra.

**Objective:** simulate a representative defence deployment — a 5-node topology
with the three profiles applied — inject four operational events (node failure,
policy change, quarantine, recovery), and measure convergence / recovery while
proving fail-closed and **zero cleartext**.

**Honest scope.** The five nodes run in-process on loopback (single host). Every
session is a **real** OOB handshake over real TCP; the **real** kinetic
`Supervisor` drives autonomous degrade/recover; the **real** `DefenceProfile` /
`CryptoPolicy` makes the enforcement decisions; the no-cleartext check inspects
the **real captured wire bytes**. This validates the orchestration end-to-end;
the kernel-level enforcement of the same decisions is measured in the eBPF Policy
Engine v2 validators (cross-referenced). Convergence here is "enforced on the
next attempt" — fleet-wide transport convergence is **[design]**.

Reproduce: `cargo test --release --test defence_deployment_tests -- --nocapture`
(`tests/defence_deployment_tests.rs`).

---

## 1. Topology & profiles — **[implemented]**

```
  Strategic Command ──▶ Regional Control ──▶ Tactical A
   (StrategicCommand)    (TacticalComms)  └─▶ Tactical B ──▶ Legacy Application
                                              (TacticalComms)   (LegacyMigration)
```

| Node | Profile | Degradation behaviour |
|---|---|---|
| Strategic Command | StrategicCommand | **fails closed** — never falls back |
| Regional Control | TacticalComms | EncryptedFallback (link stays up) |
| Tactical A / B | TacticalComms | EncryptedFallback |
| Legacy Application | LegacyMigration | controlled (non-classical) fallback |

Baseline: all four edges establish a real session with an encrypted both-ways
echo, **0 cleartext**.

## 2. Injected events & measured results — **[measured] + [tested]**

| Event | What was done | Measured | Correctness asserted |
|---|---|---|---|
| **Node failure** (Tactical A down) | Regional Control hits sustained real failures | degrade FullPqc→**EncryptedFallback in 891 µs**; after A returns, **recover to FullPqc in 174 ms**; session re-established | every session to a downed node **fails closed**; degraded posture is encrypted, never plaintext |
| **Node failure** (Strategic peer down) | Strategic Command hits sustained failures | reaches **FailClosed** | Strategic **never** enters EncryptedFallback (asserted) — highest-assurance node refuses to weaken |
| **Policy change** (Regional re-tasked Tactical→Strategic) | swap the enforced `CryptoPolicy` | a fallback connection's permit flips **true→false in 80 ns** | the new policy is enforced on the next decision (kernel push 0.66 µs avg, `docs/DEFENCE_POLICY_PROFILES.md`) |
| **Quarantine** (Tactical B) | isolate B (ingress + egress) | converged in **232 µs**, B serves **0** new sessions | both ingress and egress to/from B **fail closed**; kernel propagation 2 µs (`docs/QUARANTINE_ENGINE.md`) |
| **Recovery** (release Tactical B) | clear the quarantine | ingress + egress restored in **86 ms**, **0 cleartext** | B serves again; sessions re-establish |

Final invariant: every edge re-run, **MARKER never appeared in clear** anywhere
on the wire across the whole deployment.

> The 174 ms / 86 ms recovery figures are wall-clock for the recovery *loop* —
> they include multiple real OOB handshakes + TCP round trips on a busy
> multi-thread runtime, not a single transition (the state-machine transition
> itself is ~2.2 ns, `docs/KINETIC_STATE_MACHINE.md`). Reported as measured, with
> that composition stated.

## 3. Success criteria — status

| Criterion (mission) | Status |
|---|---|
| Defence profiles operate correctly | ✅ [tested] Strategic fails closed; Tactical/Legacy keep encrypted link; policy-change enforced |
| Quarantine propagates correctly | ✅ [tested] ingress+egress isolated, 0 served, 232 µs convergence |
| Recovery works correctly | ✅ [tested] node-failure auto-recovery to FullPqc + quarantine release, sessions re-establish |
| No plaintext state appears | ✅ [tested] MARKER never in clear on any frame, any edge, before/during/after every event |

## 4. Residual risks & limitations

- In-process loopback: no real RTT / partition / reordering between nodes; the
  convergence numbers are next-attempt enforcement, not fleet transport latency.
  Fleet convergence over a network is **[design]** (the multi-host plan in
  `docs/MULTINODE_VALIDATION.md` §5).
- Quarantine is modelled at the node boundary (isolate ingress+egress); the
  kernel cgroup enforcement of the same decision is measured separately
  (`docs/QUARANTINE_ENGINE.md`). Wiring the in-topology decision to the per-node
  kernel map is the deferred daemon-integration plumbing.
- Recovery wall-clock includes real TCP/handshake cost; a controlled-RTT harness
  would isolate the protocol recovery time from transport.

## 5. Readiness impact

A representative defence topology runs all three profiles and survives node
failure, re-tasking, quarantine, and recovery with **fail-closed preserved and
zero cleartext throughout** — measured, reproducible, no fabrication. See
`docs/DEPLOYMENT_RECOVERY_RESULTS.md` for the recovery table and
`docs/DEFENCE_READINESS_REVIEW.md` row **DEP-1**.
