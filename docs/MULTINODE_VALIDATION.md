# Multi-Node Validation — Phase 2

Tags: **[measured]** real run · **[tested]** automated assertion ·
**[implemented]** code exists · **[design]** needs external infra.

**Objective:** validate SYNTRIASS behaviour across distributed deployments —
identity distribution, session establishment, and fail-closed behaviour — at
three scale levels (3, 10, 50 nodes), with measured numbers and no extrapolation.

**Honest scope statement.** This environment is a single host. The multi-node
mesh is therefore **N independent nodes in one process on loopback** — each with
its own identity, its own `PeerRegistry`, and its own real `tokio` TCP listener.
Every session is a **real runtime OOB handshake over real TCP sockets**, finished
with an encrypted round trip in both directions, so the protocol stack,
identity-distribution correctness, and fail-closed behaviour are **[measured]**.
Cross-host WAN effects (real RTT, loss, MTU) and a networked control-plane
distribution service are **out of scope here** and marked **[design]** with a
multi-host plan (§5). No numbers are extrapolated beyond what was measured.

Reproduce: `cargo test --release --test multinode_tests -- --nocapture
--test-threads=1` (`tests/multinode_tests.rs`).

---

## 1. What was deployed & validated

| Level | Nodes | Sessions (full mesh) | Result |
|---|---:|---:|---|
| 1 | 3 | 3 | ✅ all establish, encrypted echo round-trips |
| 2 | 10 | 45 | ✅ all establish |
| 3 | 50 | 1 225 | ✅ all establish |

Each session: initiator resolves the peer by `IdentityKeyHash` from its registry
(O(1) cache), runs the compact OOB handshake over TCP, `finish()` authenticates
the responder, and a sealed message is echoed and opened — proving **both
directions agree on keys**, on every one of the 1 225 edges at Level 3.

### Identity distribution — **[tested]**

Provisioning is the real out-of-band step: for each pair a **one-time full
PQ-authenticated handshake** (ML-DSA + ML-KEM) derives the shared `auth_secret`;
both sides independently derive the **same** secret (asserted), and each registers
the other's `IdentityKeyHash`. At runtime ML-DSA never appears on the wire — the
nodes resolve each other purely by the 32-byte hash + HMAC capability.

### Fail-closed — **[tested]**

`unprovisioned_node_is_rejected_fleet_wide`: a node whose identity was **never
provisioned** into the fleet cannot establish a session — the responder's
`respond()` rejects the unknown `IdentityKeyHash` and sends **no ServerHello**. A
legitimately-known peer presenting a **wrong capability** (bad `auth_secret`) is
likewise rejected. Both are denied — fail closed, fleet-wide.

---

## 2. Measured results — **[measured]** (`docs/MULTINODE_BENCHMARKS.md` for the table)

| Metric | 3 nodes | 10 nodes | 50 nodes |
|---|---:|---:|---:|
| OOB provisioning (one-time, all pairs, 4-thread) | 0.00 s | 0.05 s | 1.13 s |
| Runtime mesh establishment (serialized) | 0.134 s | 1.980 s | 53.93 s |
| Session-establishment rate (serialized) | 22 /s | 23 /s | 23 /s |
| Process VmHWM (whole N-node mesh, one process) | 6.4 MiB | 7.2 MiB | 11.2 MiB |

- **Session rate ~23/s is a serialized floor**, not a ceiling: the test
  establishes the 1 225 edges one at a time. The per-session wall time (~43 ms)
  is dominated by sequential TCP setup + two round trips + per-node registry lock,
  not crypto (the OOB handshake itself is ~0.3 ms natively, `benches/`). Concurrent
  establishment would be far higher; that ceiling is **[design]** (§5) — not
  extrapolated here.
- **Memory scales gently**: a 50-node full mesh (1 225 provisioned peer records
  across 50 registries + 50 listeners) fits in **11.2 MiB** total. Per-node
  footprint is small and bounded by the registry (32-byte hash + pubkeys/peer).

### Policy / quarantine / recovery propagation

Per-node, these are the **kernel** operations measured in the eBPF Policy Engine
v2 workstream (single-host, kernel 6.18.5): policy push **2–9 µs** live on the
next connect (`docs/HIERARCHICAL_POLICY.md`), quarantine propagation **2 µs** /
enforcement **325 ns** (`docs/QUARANTINE_ENGINE.md`), recovery auto/manual
(`docs/QUARANTINE_ENGINE.md`), audit **~22 000 eps** (`docs/AUDIT_TELEMETRY.md`).
**Fleet-wide distribution** — fanning a policy/quarantine object out to N nodes —
requires a networked control-plane transport that is **not implemented**; the
per-node application cost is measured, the transport is **[design]** (§5). The
combined behaviour under a representative topology is exercised in Phase 3
(`docs/DEFENCE_DEPLOYMENT_SCENARIO.md`).

---

## 3. Success criteria — status

| Criterion (mission) | Status |
|---|---|
| Nodes exchange identities correctly | ✅ [tested] 3/10/50, same secret both sides, hash-resolved |
| Policies propagate correctly | ◑ per-node kernel push [measured]; fleet transport [design] |
| Quarantine propagates correctly | ◑ per-node [measured] (2 µs); fleet transport [design] |
| Fail-closed preserved | ✅ [tested] unprovisioned + wrong-capability rejected fleet-wide |
| Recovery preserved | ✅ [tested] kinetic + quarantine recovery (single-node, prior phases); Phase 3 exercises it in-topology |

---

## 4. Scaling limits (measured, not extrapolated)

- Largest deployment executed here: **50 nodes / 1 225 sessions**, single host,
  one process. This is the achievable scale in this environment.
- The serialized establishment time grows with the pair count (O(N²) edges in a
  full mesh) — 53.9 s at 50 nodes. A real fleet is not full-mesh and establishes
  concurrently; do not read 23/s as a system throughput limit.
- 10/50-node **AWS / multi-host** runs and concurrent establishment are
  **[design]** (§5).

## 5. Multi-host execution plan — **[design]**

1. **3-node real-host** (cheapest first): 3 Ubuntu VMs (or containers on a bridge
   network), one identity each, provision pairwise out-of-band, run the same
   `multinode_tests` harness pointed at real IPs instead of loopback. Adds real
   RTT to the session numbers.
2. **10-node** across two hosts / a small k8s cluster (one pod per node), with the
   eBPF policy engine attached per-pod (the per-pod cgroup attach is the existing
   `scripts/ebpf_*` validators run inside each pod).
3. **50-node** on a managed cluster; measure concurrent establishment rate and
   per-node CPU/mem under `perf`/`pidstat`.
4. **Control-plane distribution service**: a signed policy/quarantine object
   fan-out (the producer is the kinetic `Supervisor`); measure fleet convergence
   time. This is the missing transport above.

---

## 6. Residual risks

- Loopback hides real network failure modes (RTT, partitions, reordering); the
  battlefield-resilience suite covers degraded single links, but multi-host
  partition behaviour is **[design]**.
- No networked policy/quarantine distribution transport yet — per-node enforcement
  is proven, fleet convergence is Phase 3 (in-process topology) + the multi-host
  plan.
- Serialized establishment understates throughput; concurrent rate **[design]**.

## 7. Readiness impact

Identity distribution, session establishment, and fail-closed behaviour are
**proven correct at 50 nodes / 1 225 real sessions** with a measured, gently-
scaling memory footprint, plus a concrete multi-host plan. See
`docs/DEFENCE_READINESS_REVIEW.md` row **MN-1**.
