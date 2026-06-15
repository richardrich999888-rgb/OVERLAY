# SYNTRIASS Overlay — TRL-5 Readiness Release Notes

**Milestone:** TRL-5 Defence Readiness Validation Package
**Branch:** `claude/beautiful-noether-soSdW` · 60 commits · 165 files · +55 224 / −415 lines
**Evidence discipline:** every claim below is tagged **[measured]** (real run on
this host), **[tested]** (automated assertion), **[implemented]** (code exists),
**[measured-emulated]** (real ARM64 ISA execution under QEMU; timings are the
emulator's), or **[design]** (planned; not executed). No fabricated benchmarks;
no extrapolation beyond measured results.

---

## Executive Summary

This release consolidates fourteen defence-engineering workstreams that
transform the SYNTRIASS Overlay from a single-host prototype into an
evidence-backed TRL-5 platform: a post-quantum, fail-closed communications
overlay with kernel-native policy enforcement, autonomous operational recovery,
sovereign key storage, a validated identity lifecycle, and measured behaviour
under degraded, multi-node, and adversarial conditions. All 19 tracked findings
in the Defence Readiness Review were re-assessed downward with committed
evidence; the full reproduction commands ship in-repo.

## Major Features

- **Hybrid PQC control plane** — X25519+ML-KEM-768/1024, Ed25519+ML-DSA-65,
  HKDF-SHA256, AES-256-GCM; hardened record layer (anti-replay window, rekey
  ratchet, lifecycle) **[tested]** (`docs/PQC_PROTOCOL_SPEC.md`).
- **Out-of-band identity (PERF-1)** — ML-DSA moved to one-time provisioning;
  runtime handshake 13 050 → **2 464 B (−81.1 %)** and 1 846 → **328 µs
  (−82.2 %)**, 0 ML-DSA bytes on the wire **[measured]**
  (`docs/OUT_OF_BAND_IDENTITY.md`).
- **Universal interception (C1)** — kernel `cgroup/connect4` eBPF data plane
  replaces LD_PRELOAD; 7/7 runtimes intercepted incl. the 4 LD_PRELOAD blind
  spots; fail-closed EPERM **[measured]** (`docs/UNIVERSAL_INTERCEPTION.md`).
- **eBPF Policy Engine v2 (6 phases)** — structured 80-byte policy objects in
  BPF maps (lookup **343 ns**), Global→Node→App→Session hierarchy with
  Highest-Priority-Wins (**895 ns** resolve), cryptographic policy enforcement
  at kernel + daemon (**3.78 ns**/decision), quarantine engine (**2 µs**
  propagate / **325 ns** enforce), categorized audit pipeline (**~22 000 eps**,
  exact drop accounting), three deployable defence profiles (switch
  **0.66 µs** avg) **[measured]** (`docs/POLICY_OBJECT_MODEL.md` →
  `docs/DEFENCE_POLICY_PROFILES.md`).
- **Kinetic state machine (PERF-4)** — autonomous FullPqc ↔ EncryptedFallback ↔
  FailClosed transitions driven by real handshake outcomes; failover **2.0 ms**,
  recovery **8.1 ms**, **no `Plaintext` variant exists** (compiler-enforced)
  **[measured]** (`docs/KINETIC_STATE_MACHINE.md`).
- **Sovereign key storage (KS-1)** — software AES-GCM sealing fully tested;
  TPM2 (swtpm) and PKCS#11 (SoftHSM2) backends validated end-to-end through the
  real adapter **[tested]**; physical-device acceptance **[design]**
  (`docs/KEY_STORAGE_ARCHITECTURE.md`).
- **Identity lifecycle (IL-1)** — enrollment+PoP, issuance, rotation, CRL
  revocation with monotonic propagation, expiry, recovery, air-gap
  provisioning; 28 tests driving the real handshake **[tested]**
  (`docs/IDENTITY_LIFECYCLE.md`).

## Security Improvements

- **Handshake DoS hardening (C6)** — stateless-cookie admission gate on the
  live daemon path; per-source + global PQC-rate + concurrency caps; a
  5 000-source distributed flood is held to the global burst (25 PQC ops)
  **[measured]** (`docs/HANDSHAKE_DOS_HARDENING.md`).
- **Fail-closed assurance (FC-1)** — Miri (UB), Loom (exhaustive concurrency),
  cargo-fuzz (ASan), property + leakage tests; `#![deny(unused_must_use)]`;
  **2 real bugs found and fixed** (a misaligned-reference UB; an attacker-
  reachable integer overflow in epoch handling) **[tested]**
  (`docs/FAIL_CLOSED_ASSURANCE.md`).
- **Cryptographic policy** — FullPqcOnly / HybridOnly / FallbackAllowed /
  HardwareKeyRequired / NoClassicalFallback enforced at both layers with a
  shared bit-compatible flag set; **every `Unknown` attribute is denied**
  **[tested]** (`docs/CRYPTO_POLICY.md`).
- **Zero plaintext, structurally** — no plaintext operational state is
  representable anywhere (kinetic modes, profiles, postures); wire-byte capture
  in the deployment scenario confirms a plaintext marker **never** appears
  **[tested]**.
- One ARM64 portability fix with a security flavour: the kTLS availability
  probe now classifies `EINVAL` at ULP-attach as *unavailable* (fail-closed)
  rather than *present* (`src/kernel_native.rs`).

## Validation Workstreams

| Workstream | Evidence | Headline result |
|---|---|---|
| Battlefield resilience (C2) | `docs/BATTLEFIELD_RESILIENCE.md`, `NETEM_RESULTS.md`, `RECOVERY_ANALYSIS.md` | loss ladder 10–45 % with 0 plaintext leaks; reconnect ~3.5 ms; 249 hs/s under congestion; real `tc netem` unavailable here → host plan **[design]** |
| ARM64 (ARM-1) | `docs/ARM64_VALIDATION.md`, `ARM64_BENCHMARKS.md` | full suite **26/26, 193 tests** on the real ARM64 ISA (QEMU+binfmt); wire bytes byte-identical; native CI committed (`.github/workflows/arm64.yml`); native silicon **[design]** |
| Multi-node (MN-1) | `docs/MULTINODE_VALIDATION.md`, `MULTINODE_BENCHMARKS.md` | 3/10/50-node meshes, **1 225 real OOB sessions** all establish; unprovisioned identities rejected fleet-wide; VmHWM 11.2 MiB at 50 nodes; multi-host **[design]** |
| Defence deployment (DEP-1) | `docs/DEFENCE_DEPLOYMENT_SCENARIO.md`, `DEPLOYMENT_RECOVERY_RESULTS.md` | 5-node topology, 3 profiles, 4 injected events; Strategic Command **never** falls back; quarantine converges 232 µs; **zero cleartext throughout** |
| Evidence package | `docs/defence-evidence/00_INDEX.md`–`08_*` | consolidated DRDO/iDEX/red-team/kernel/crypto review set |

## Benchmark Improvements

| Metric | Before | After | Tag |
|---|---:|---:|---|
| Runtime handshake size | 13 050 B | **2 464 B** (−81.1 %) | [measured] |
| Runtime handshake latency | 1 846 µs | **328 µs** (−82.2 %) | [measured] |
| Policy decision (kernel) | single global flag | **343 ns** lookup / **895 ns** 4-level resolve | [measured] |
| Posture/profile change | manual | **0.66–9 µs**, live next connect | [measured] |
| Failover / recovery | manual | **2.0 ms / 8.1 ms** autonomous | [measured] |
| Quarantine isolate | none | **2 µs** propagate, **325 ns** enforce | [measured] |
| Audit | none | **~22 000 eps**, 0 silent loss | [measured] |
| kTLS data-plane throughput | 12.8–15.5 % line rate | secrets bridge done; throughput **BLOCKED** (no TLS ULP here); recommended target ≥28 %/~2× | [design] |

## Defence Readiness Improvements

All 19 ledger findings re-assessed with evidence (`docs/READINESS_DELTA.md` for
the full table): C6, FC-1, IL-1, C1, PERF-1/3/4, EBPF-P1–P6 → **Low**;
KS-1, C2 → **Low–Medium**; PERF-2 → **Medium (partial)**; ARM-1, MN-1, DEP-1 →
**Medium**. CI gate: fmt + clippy `-D warnings` + locked release build + full
test suite (28 suites x86_64 green; 26 suites ARM64-emulated green) + native
ARM64 workflow.

## Known Limitations

- **kTLS throughput uplift is unproven here** — this container has no TLS ULP;
  the key bridge is implemented + tested, the throughput number requires a
  kTLS-enabled host **[design]**.
- **ARM64 timings are emulated** — correctness is proven on the real ISA;
  silicon performance awaits the committed native CI / Graviton plan.
- **Multi-node runs are single-host loopback** — protocol correctness and
  fail-closed are proven; real RTT, partitions, and a networked policy
  distribution transport are **[design]**.
- **Daemon-loop wiring** — the kinetic Supervisor, `CryptoPolicy::enforce`, and
  the quarantine producer are validated components not yet wired into the live
  daemon's connection loop.
- TPM/HSM validated against software substitutes (swtpm/SoftHSM2); physical
  device acceptance pending.

## Remaining Risks

- No external cryptographic review yet (protocol + implementation).
- Kernel policy engine validated on x86_64 kernel 6.18.5; ARM64-kernel eBPF
  load is compile-proven + CI-planned only.
- Fleet-scale convergence (policy/quarantine fan-out over a network) unmeasured.
- Sustained multi-core audit-pipeline ceiling unmeasured (source-bounded here).

## Next Roadmap

1. External cryptographic review (protocol spec + `src/crypto`).
2. Native ARM hardware benchmarking (Graviton/Ampere; CI already committed).
3. Multi-host deployment validation (3 → 10 → 50 real nodes, k8s per-pod attach).
4. PQC → kTLS production bridge on a TLS-ULP host (throughput target ≥28 % line).
5. Production eBPF policy layer: daemon-loop integration + fleet distribution
   transport + expired-entry GC.
6. Defence pilot deployment under a defence evaluation authority.
