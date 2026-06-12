# Multi-Node Benchmarks — Phase 2

Companion to `docs/MULTINODE_VALIDATION.md`. All rows **[measured]** on this host
(x86_64, 4 CPUs) by `tests/multinode_tests.rs`. Single-process loopback mesh —
see the validation doc §scope. No extrapolation.

Reproduce:
```sh
cargo test --release --locked --test multinode_tests -- --nocapture --test-threads=1
```

## 1. Mesh establishment (real OOB sessions over real TCP)

| Nodes | Full-mesh sessions | OOB provisioning (one-time, 4-thread) | Runtime establishment (serialized) | Rate (serialized) | Process VmHWM |
|---:|---:|---:|---:|---:|---:|
| 3 | 3 | 0.00 s | 0.134 s | 22 sessions/s | 6 436 KiB |
| 10 | 45 | 0.05 s | 1.980 s | 23 sessions/s | 7 164 KiB |
| 50 | 1 225 | 1.13 s | 53.930 s | 23 sessions/s | 11 244 KiB |

Notes:
- **Provisioning** is the one-time out-of-band full PQ handshake per pair (run
  4-way parallel here); it is not on the runtime path.
- **Establishment** is serialized (one edge at a time); the ~43 ms/session wall
  time is TCP + 2 round trips + per-node registry lock, **not** crypto (OOB
  handshake ≈ 0.3 ms native, see `benches/oob_benchmarks.rs`). The rate is a
  **floor**; concurrent establishment is **[design]**.
- **VmHWM** is the whole N-node mesh in one process — an upper bound on aggregate
  footprint; per-node share at 50 nodes ≈ 225 KiB incremental.

## 2. Memory scaling (measured points only)

| Nodes | Sessions | VmHWM (KiB) | Δ vs 3-node |
|---:|---:|---:|---:|
| 3 | 3 | 6 436 | — |
| 10 | 45 | 7 164 | +728 |
| 50 | 1 225 | 11 244 | +4 808 |

50 nodes / 1 225 provisioned peer records + 50 registries + 50 live listeners ⇒
**11.2 MiB** total. Linear-ish in node+session count; no pathological growth.

## 3. Per-node policy/quarantine/audit (cross-reference — single-host kernel)

These are **not** re-measured per-node here (each node runs the same kernel engine
already measured on kernel 6.18.5):

| Operation | Measured | Source |
|---|---:|---|
| Policy object push (propagation to one node's kernel) | 2–9 µs, live next connect | `docs/HIERARCHICAL_POLICY.md` |
| Hierarchical resolve + decision | 895 ns | `docs/HIERARCHICAL_POLICY.md` |
| Quarantine propagation / enforcement | 2 µs / 325 ns | `docs/QUARANTINE_ENGINE.md` |
| Quarantine manual release | 15 µs | `docs/QUARANTINE_ENGINE.md` |
| Audit pipeline throughput | ~22 000 eps, 0 drops | `docs/AUDIT_TELEMETRY.md` |
| Profile apply / switch | 3–9 µs / 0.66 µs | `docs/DEFENCE_POLICY_PROFILES.md` |

Fleet-wide convergence (these × N + a networked distribution transport) is
**[design]**; Phase 3 exercises the combined behaviour in an in-process topology.
