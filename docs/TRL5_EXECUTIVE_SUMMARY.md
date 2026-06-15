# SYNTRIASS Overlay — TRL-5 Executive Summary

*Audience: iDEX reviewers, defence evaluators, technical investors. Two pages.*

## Problem

Defence communications face a twin threat: **harvest-now-decrypt-later quantum
adversaries**, and **contested, degraded networks** where classical secure links
either fail open (leaking plaintext) or fail dead (losing the mission). Existing
VPN/TLS stacks were designed for neither: they negotiate classical cryptography,
trust the endpoint's userspace, degrade unpredictably under loss and jamming,
and offer no kernel-level guarantee that a compromised or misconfigured node
cannot speak in the clear.

## Innovation

SYNTRIASS is a **post-quantum, fail-closed communications overlay** with a
kernel-native policy engine. Five properties distinguish it:

1. **Hybrid PQC by construction** — X25519+ML-KEM with Ed25519+ML-DSA identity;
   an out-of-band identity layer removes the 10.5 KB ML-DSA cost from every
   runtime connection (handshake −81 % size, −82 % latency, measured).
2. **Plaintext is unrepresentable** — no operational mode, profile, or posture
   in the codebase can express an unencrypted channel; this is enforced by the
   type system and verified by wire-byte capture, fuzzing, and model checking.
3. **Kernel-native enforcement** — an eBPF policy engine makes the *kernel*
   deny non-compliant egress (343 ns policy lookup; quarantine of a compromised
   workload enforced in 325 ns), so policy survives userspace compromise.
4. **Autonomous operational recovery** — a kinetic state machine degrades
   FullPqc → EncryptedFallback → FailClosed and recovers on real handshake
   outcomes (2 ms failover), with security lockdowns that only manual action
   clears.
5. **Deployable defence profiles** — Strategic Command (never falls back),
   Tactical Communications (resilient encrypted fallback), Legacy Migration
   (controlled interop) — one object, enforced identically at daemon and kernel,
   switchable in under a microsecond.

## Validation

All evidence is measured, reproducible, and committed (no fabricated numbers;
unexecutable items are explicitly tagged *design*):

- **Adversarial:** 5 000-source handshake flood contained; Miri/Loom/fuzzing
  found and fixed 2 real bugs; every "unknown" security attribute is denied.
- **Degraded:** 10–45 % loss ladder with zero plaintext leaks; reconnect
  ~3.5 ms; 249 handshakes/s under congestion; daemon-kill and memory-exhaustion
  fail closed.
- **Scale:** 3/10/50-node meshes — 1 225 real PQC sessions, unprovisioned
  identities rejected fleet-wide; 11 MiB footprint at 50 nodes.
- **End-to-end:** a 5-node Strategic→Regional→Tactical→Legacy deployment
  survived node failure, re-tasking, quarantine, and recovery with fail-closed
  preserved and zero cleartext throughout.
- **Portability:** full test suite (193 tests) passes on the ARM64 ISA;
  byte-identical wire artifacts; native ARM64 CI committed.
- **Sovereignty:** keys sealed to TPM2/PKCS#11 backends through the production
  adapter (software-substitute validation; hardware acceptance planned).

## Current TRL

**TRL 5** — component and breadboard validation in a relevant (simulated
contested) environment, on commodity Linux with real kernel enforcement. The
step to TRL 6 requires the items below executed in a representative
environment (real hardware, real multi-host networks, pilot users).

## Remaining Gaps

1. **External cryptographic review** of the protocol and implementation.
2. **Native ARM hardware benchmarking** (Graviton/Ampere; CI in place).
3. **Multi-host deployment validation** (real RTT, partitions, fleet policy
   distribution transport).
4. **PQC→kTLS production bridge** on a TLS-ULP kernel (key bridge done;
   throughput uplift target ≥2× unverified here).
5. **Production integration** of the validated policy/recovery components into
   the live daemon loop.
6. **Defence pilot deployment** under an evaluation authority.

## Funding Use Plan

| Allocation | Purpose | Exit criterion |
|---|---|---|
| 30 % | Independent cryptographic review + remediation | published review, findings closed |
| 25 % | Hardware validation: ARM64 silicon, physical TPM/HSM, kTLS hosts | native benchmark report replacing every [design] tag |
| 25 % | Multi-host pilot: 10→50 real nodes, fleet policy distribution, k8s integration | TRL-6 field-representative demonstration |
| 20 % | Production hardening: daemon integration, packaging, operator tooling, accreditation documentation | pilot-ready release + defence evaluation entry |

*Full evidence: `docs/RELEASE_NOTES_TRL5.md`, `docs/READINESS_DELTA.md`,
`docs/DEFENCE_READINESS_REVIEW.md`, and the per-workstream documents they index.*
