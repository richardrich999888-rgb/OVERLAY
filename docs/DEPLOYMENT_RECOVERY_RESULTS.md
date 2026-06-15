# Deployment Recovery Results — Phase 3

Companion to `docs/DEFENCE_DEPLOYMENT_SCENARIO.md`. All rows **[measured]** by a
single run of `tests/defence_deployment_tests.rs` (x86_64, 4-thread tokio,
in-process loopback topology). No extrapolation.

Reproduce:
```sh
cargo test --release --locked --test defence_deployment_tests -- --nocapture
```

## 1. Convergence & recovery

| Event | Metric | Measured |
|---|---|---:|
| Node failure (Tactical A) | Regional Control degrade FullPqc→EncryptedFallback | **891 µs** |
| Node failure (Tactical A) | recovery to FullPqc after node returns (recovery loop, real sessions) | **174 ms** |
| Node failure (Strategic peer) | Strategic Command outcome | **FailClosed** (never EncryptedFallback) |
| Policy change (Regional Tactical→Strategic) | fallback-permit flip convergence (decision) | **80 ns** |
| Quarantine (Tactical B) | ingress+egress isolation convergence | **232 µs** |
| Quarantine (Tactical B) | sessions served while quarantined | **0** |
| Recovery (release Tactical B) | ingress+egress restoration (real sessions) | **86 ms** |
| Session recovery | re-established after node-failure recovery | **yes** |

## 2. Fail-closed & zero-cleartext correctness

| Assertion | Result |
|---|---|
| Session to a downed node | fails closed (no key agreement) ✓ |
| Strategic Command never enters EncryptedFallback | ✓ (asserted over 6 sustained failures) |
| Strategic Command reaches FailClosed on sustained failure | ✓ |
| Quarantined node refuses ingress AND egress | ✓ |
| Quarantined node serves 0 new sessions | ✓ |
| Released node serves again, sessions re-establish | ✓ |
| MARKER plaintext on the wire — baseline / during events / final | **never seen** (0 cleartext) ✓ |

## 3. Composition note (honesty)

The 174 ms / 86 ms figures are wall-clock for the **recovery loop**, which runs
several real OOB handshakes + TCP round trips on a contended runtime — not a
single state transition. The kinetic transition itself is ~2.2 ns
(`docs/KINETIC_STATE_MACHINE.md`); the kernel posture/quarantine push is 0.66–2 µs
(`docs/DEFENCE_POLICY_PROFILES.md`, `docs/QUARANTINE_ENGINE.md`). The deployment
figures are the *end-to-end* numbers including transport, reported as measured.

## 4. Cross-reference (single-host kernel, already measured)

| Decision in this scenario | Kernel-enforced equivalent | Source |
|---|---|---|
| Profile re-task | global policy push 0.66 µs avg / 31 µs max | `docs/DEFENCE_POLICY_PROFILES.md` |
| Quarantine isolate | propagation 2 µs, enforcement 325 ns | `docs/QUARANTINE_ENGINE.md` |
| Posture transition | flag push 1–3 µs, FailClosed→EPERM | `docs/KINETIC_STATE_MACHINE.md`, `docs/EBPF_POLICY_ENGINE.md` |
