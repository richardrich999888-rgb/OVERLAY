# Readiness Delta — TRL-5 Milestone

Status delta for every workstream in this milestone, cross-referenced to its
evidence. Statuses use the Defence Readiness Review's risk scale; "Previous"
is the state before the workstream ran on this branch. Full ledger:
`docs/DEFENCE_READINESS_REVIEW.md`.

| Finding | Previous Status | Current Status | Evidence |
|----------|----------|----------|----------|
| **PQC Hardening** (PQC-2: key-wear, no anti-replay/rekey) | Medium — record layer had no sequencing/replay/rekey | **Mitigated** — explicit sequencing, anti-replay window, rekey ratchet, lifecycle; fuzz-found epoch overflow fixed; zero false accepts [tested] | `docs/PQC_PROTOCOL_SPEC.md §4`; `src/crypto/session.rs`; `tests/session_hardening_tests.rs` |
| **Handshake DoS** (C6: PQC work before peer validation) | High — flood drives CPU exhaustion | **Low** — stateless-cookie gate on the live daemon path; per-source + global caps; 5 000-source flood held to 25 PQC ops [measured] | `docs/HANDSHAKE_DOS_HARDENING.md`; `src/handshake_guard.rs`; `tests/handshake_dos_*` |
| **Fail-Closed Assurance** (FC-1) | High — no automated no-cleartext/no-panic/concurrency proof; 85/86 unsafe blocks unaudited | **Low** — Miri + Loom + cargo-fuzz run; property/leakage/concurrency suites; 2 real bugs (misaligned-ref UB, epoch overflow) found & fixed; `#![deny(unused_must_use)]` [tested] | `docs/FAIL_CLOSED_ASSURANCE.md`; `tests/fail_closed_properties.rs`, `loom_model.rs`; `fuzz/`; `scripts/run_miri.sh` |
| **Universal Interception** (C1: LD_PRELOAD blind spots) | High — static/Go/musl/direct-syscall bypass | **Low** — kernel `cgroup/connect4` eBPF data plane; 7/7 runtimes intercepted; fail-closed EPERM [measured] | `docs/UNIVERSAL_INTERCEPTION.md`; `ebpf/c/`; `scripts/ebpf_coverage_validate.sh` |
| **Key Storage** (KS-1: raw seeds on disk) | High | **Low–Medium** — backend-agnostic protection layer; software AES-GCM sealing fully tested; sealed-to-hardware proven (different TPM can't unseal) [tested]; physical device [design] | `docs/KEY_STORAGE_ARCHITECTURE.md`; `src/keystore.rs`; `tests/keystore_external_tests.rs` |
| **TPM Integration** | None | **Validated against swtpm** end-to-end through the real Rust adapter (persistent primary, sealed wrap/unwrap) [tested]; physical TPM acceptance [design] | `docs/TPM_INTEGRATION.md`; `scripts/keystore/` |
| **HSM Integration** | None | **Validated against SoftHSM2/PKCS#11** (raw ECDSA on pre-hashed input, token-sealed keys) [tested]; production HSM acceptance [design] | `docs/HSM_INTEGRATION.md`; `scripts/keystore/` |
| **Battlefield Resilience** (C2) | Medium — unproven under degradation | **Low–Medium** — loss ladder 10/20/30/45 % (0 plaintext leaks), reconnect ~3.5 ms, CPU-starvation 30/30, 249 hs/s congestion, crash/memory fail-closed [measured]; real `tc netem` unavailable here → host plan [design] | `docs/BATTLEFIELD_RESILIENCE.md`, `NETEM_RESULTS.md`, `RECOVERY_ANALYSIS.md`; `tests/battlefield_resilience.rs` |
| **ARM64 Validation** (ARM-1) | High — entirely unvalidated | **Medium** — cross-build succeeds; **26/26 suites, 193 tests pass on the real ARM64 ISA** (QEMU+binfmt); wire bytes byte-identical; 1 portability bug fixed; native CI committed [measured-emulated]; silicon perf [design] | `docs/ARM64_VALIDATION.md`, `ARM64_BENCHMARKS.md`; `.github/workflows/arm64.yml` |
| **Multi-Node Validation** (MN-1) | High — distributed behaviour unvalidated | **Medium** — 3/10/50-node meshes; **1 225 real OOB sessions** establish with encrypted echo; unprovisioned + wrong-capability identities rejected fleet-wide; VmHWM 11.2 MiB @50 [measured]; multi-host transport [design] | `docs/MULTINODE_VALIDATION.md`, `MULTINODE_BENCHMARKS.md`; `tests/multinode_tests.rs` |
| **Defence Deployment Validation** (DEP-1) | High — no end-to-end scenario | **Medium** — 5-node topology, 3 profiles, 4 injected events (failure/re-task/quarantine/recovery) all measured; Strategic Command never falls back; **zero cleartext throughout** [measured] | `docs/DEFENCE_DEPLOYMENT_SCENARIO.md`, `DEPLOYMENT_RECOVERY_RESULTS.md`; `tests/defence_deployment_tests.rs` |

## Supporting deltas delivered on this branch (same evidence discipline)

| Finding | Previous → Current | Evidence |
|---|---|---|
| IL-1 Identity lifecycle | High → **Low** | `docs/IDENTITY_LIFECYCLE.md`, `OFFLINE_PROVISIONING.md`; `src/identity.rs` |
| PERF-1 Out-of-band identity | High → **Low** (−81.1 % size, −82.2 % latency) | `docs/OUT_OF_BAND_IDENTITY.md`; `benches/oob_benchmarks.rs` |
| PERF-2 kTLS bridge | Med → **Medium (partial)** — secrets bridge tested; throughput BLOCKED (no TLS ULP) | `docs/KTLS_INTEGRATION.md`; `src/kernel_native.rs` |
| PERF-3 eBPF state layer | Med → **Low** | `docs/EBPF_POLICY_ENGINE.md`; `scripts/ebpf_policy_validate.sh` |
| PERF-4 Kinetic state machine | Med → **Low** | `docs/KINETIC_STATE_MACHINE.md`; `src/kinetic.rs` |
| EBPF-P1…P6 Policy Engine v2 | Med → **Low** (×6) | `docs/POLICY_OBJECT_MODEL.md`, `HIERARCHICAL_POLICY.md`, `CRYPTO_POLICY.md`, `QUARANTINE_ENGINE.md`, `AUDIT_TELEMETRY.md`, `DEFENCE_POLICY_PROFILES.md` |
