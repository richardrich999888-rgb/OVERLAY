# SYNTRIASS Overlay — Defence Evidence Package

**Audience:** DRDO · iDEX · Red Team · Linux kernel engineers · cryptographers.
**Branch/commit:** `claude/beautiful-noether-soSdW` (see git log for the exact
SHA per claim). **Date:** 2026-06-11.

This package consolidates the evidence for the SYNTRIASS Overlay — a split-plane,
post-quantum, fail-closed communications overlay — at the close of a sequence of
hardening tracks (C6 anti-DoS, FC-1 fail-closed assurance, IL-1 identity
lifecycle, C1 universal interception, plus PQC record-layer hardening).

## Evidence-tag legend (applied to every material statement)

| Tag | Meaning |
|---|---|
| **[implemented]** | Code exists in the tree. |
| **[tested]** | Covered by an automated test that passes here. |
| **[measured]** | A benchmark/experiment produced a concrete number in this environment. |
| **[design]** | Specified; not built/validated — requires external infrastructure. |
| **[future]** | Roadmap; not started. |

**Ground rule (enforced throughout):** no claim is made without one of the above
tags, and `[measured]`/`[tested]` claims name a reproducing command or artifact.
Where an item could only be designed (no infra), it is tagged `[design]` and the
required infrastructure is stated — it is **never** presented as validated.

## Contents

| # | Document | Scope |
|---|---|---|
| 1 | `01_THREAT_MODEL.md` | Adversary, assets, attack surface, threats → mitigations |
| 2 | `02_SECURITY_MODEL.md` | Guarantees, crypto constructions, trust boundaries, fail-closed invariants |
| 3 | `03_ARCHITECTURE.md` | Split-plane v2 architecture (eBPF data plane + control daemon + PQC + kTLS + identity) |
| 4 | `../DEFENCE_READINESS_REVIEW.md` | Living readiness review + per-finding reassessments |
| 5 | `04_TRL_ASSESSMENT.md` | Per-component TRL with justification + overall |
| 6 | `05_RISK_REGISTER.md` | Enumerated risks, severity, status, mitigation, residual |
| 7 | `06_BENCHMARK_REPORT.md` | Measured performance (handshake, throughput, eBPF, fuzz, loss ladder) |
| 8 | `07_VALIDATION_REPORT.md` | Consolidated test/validation inventory + results |
| 9 | `08_RESIDUAL_RISK_REPORT.md` | What remains unproven/at-risk, honestly |

Supporting deep-dives (referenced throughout): `../PQC_PROTOCOL_SPEC.md`,
`../HANDSHAKE_DOS_HARDENING.md`, `../FAIL_CLOSED_ASSURANCE.md`,
`../IDENTITY_LIFECYCLE.md`, `../UNIVERSAL_INTERCEPTION.md`.

---

## Headline result

A single eBPF `cgroup/connect4` program **[measured]** intercepted **7/7**
process runtimes — including the four that LD_PRELOAD is structurally blind to
(static binaries, Go, musl-static, raw `syscall(SYS_connect)`) — and enforced a
**fail-closed `EPERM` deny** against a port with a live listener
(`ebpf/COVERAGE_REPORT.txt`). The post-quantum control plane (hybrid X25519 +
ML-KEM, Ed25519 + ML-DSA-65), the anti-replay/rekey record layer, the stateless-
cookie anti-DoS gate, and the identity-credential lifecycle are all **[tested]**
and, where applicable, **[measured]**. Fail-closed assurance was validated with
**Miri (0 UB)**, **Loom (exhaustive)**, and **cargo-fuzz** — the last of which
**found and we fixed a real fail-open overflow bug**.

## Final defence-readiness score

Composite of nine pillars, each scored 0–5 (0 = absent, 3 = implemented+tested
in-sandbox, 4 = measured/validated on a relevant host, 5 = validated in a fielded/
integrated environment). Scores reflect **only** what is tagged `[tested]`/
`[measured]` here.

| Pillar | Score | Basis |
|---|:--:|---|
| Universal interception | **4 / 5** | eBPF 7/7 coverage + enforcement **[measured]** on kernel 6.18; K8s/IPv6/UDP **[design]** |
| PQC confidentiality | **4 / 5** | hybrid handshake, record layer, downgrade resistance **[tested]**; latencies **[measured]** |
| Anti-DoS (C6) | **4 / 5** | gate on the live daemon path; PQC-invocation counts **[measured]** |
| Fail-closed assurance | **4 / 5** | property + Miri + Loom + fuzz **[measured]**; 2 real bugs fixed |
| Identity lifecycle | **3 / 5** | full software lifecycle **[tested]**; TPM2/PKCS#11/HSM **[design]** |
| Resilience (loss/chaos) | **3 / 5** | record-layer loss ladder + daemon-kill **[measured/tested]**; real `tc netem` **[design]** |
| Sovereign deployment (ARM/air-gap) | **2 / 5** | air-gap provisioning **[tested]**; ARM64 hardware **[design]** |
| Integrated system demonstration | **2 / 5** | subsystems validated; end-to-end multi-node demo **[design]** |
| Independent assurance / CI gating | **3 / 5** | full CI gate green; privileged BPF + nightly lanes **[design]** |

**Composite: 29 / 45 ≈ 64% — band: "Conditional / pre-trial ready".**

Interpretation for reviewers: the **core technical risks have been retired with
real evidence** (interception universality, fail-closed soundness, PQC channel,
anti-DoS). The remaining points are **integration and fielded-environment**
gaps (K8s, ARM hardware, TPM/HSM, real netem, a multi-node demo, privileged CI) —
honestly scoped as `[design]`, none blocked by a known defect.

## Final TRL estimate

**TRL 5 overall**, with the universal-interception data plane at **TRL 6 on the
validated host**.

- Multiple subsystems are validated in a relevant environment (real kernel eBPF
  interception **[measured]**; PQC channel + record layer + anti-DoS + identity
  lifecycle **[tested]**) → **TRL 5**.
- The eBPF interception was demonstrated end-to-end against seven real runtimes on
  a representative kernel (6.18) → **TRL 6** for that subsystem on that host.
- **Gate to a defensible TRL 6 overall:** an integrated multi-node demonstration
  (eBPF data plane → control daemon → PQC handshake → kTLS, across hosts) plus
  fielded-environment validation (ARM64, TPM/HSM, real `tc netem`, K8s). All are
  `[design]` with stated infrastructure; none requires new research.

> This estimate is deliberately conservative. It counts only what is tagged
> `[tested]`/`[measured]` in this environment and does not credit `[design]` or
> `[future]` items toward TRL.
