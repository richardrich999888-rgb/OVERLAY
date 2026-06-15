# SYNTRIASS Overlay — iDEX Open Challenge Executive Summary

*Read this first. Two pages. Every claim is tagged to repository evidence:
**[measured]** real run · **[tested]** automated assertion · **[implemented]**
code exists · **[design]** planned, not yet executed. No claim is un-tagged.*

---

## The problem

Defence communications face two simultaneous, compounding threats:

1. **Harvest-now-decrypt-later (HNDL).** Adversaries record encrypted defence
   traffic today and decrypt it once a cryptographically-relevant quantum
   computer exists. Every classical-key link (RSA/ECDH/TLS) carrying a secret
   with a shelf-life beyond ~10 years is **already compromised in transit**.
2. **Contested, degraded networks.** Tactical links jam, drop, and partition.
   Conventional secure stacks either **fail open** (leak plaintext when crypto
   negotiation fails) or **fail dead** (lose the mission), and trust the
   endpoint's userspace — which a compromised host can bypass.

No fielded Indian-sovereign solution today combines **post-quantum
confidentiality**, **kernel-enforced fail-closed behaviour**, and **drop-in
migration** for existing applications.

## The innovation — SYNTRIASS Overlay

A **post-quantum, fail-closed communications overlay** that upgrades existing
applications to quantum-safe transport **without source changes**, enforced in
the **Linux kernel** so a compromised userspace cannot leak plaintext.

| Pillar | What it is | Evidence |
|---|---|---|
| **Hybrid PQC** | X25519 + ML-KEM (NIST FIPS 203) key exchange, Ed25519 + ML-DSA (FIPS 204) identity, AES-256-GCM records | [implemented]+[tested] |
| **Out-of-band identity** | ML-DSA moved to one-time provisioning; runtime handshake **−81 % size, −82 % latency**, 0 ML-DSA bytes on the wire | **[measured]** |
| **Kernel-native policy** | eBPF `cgroup/connect4` engine denies non-compliant egress in **343 ns**; quarantine a node in **325 ns** | **[measured]** |
| **Zero-plaintext, structurally** | no operational mode/posture/profile can represent plaintext — compiler-enforced, fuzz-verified | [tested] |
| **Autonomous recovery** | FullPqc → EncryptedFallback → FailClosed transitions on real link outcomes; failover **2 ms** | **[measured]** |
| **Deployable & air-gapped** | install→configure→validate on a fresh host; offline identity/policy distribution; **120-node** fleet management | [tested] |

## Validation status (repository-backed)

- **Adversarial:** a 5 000-source handshake flood is contained to 25 PQC ops
  **[measured]**; Miri + Loom + cargo-fuzz found and fixed 2 real bugs [tested].
- **Degraded:** 10–45 % packet-loss ladder with **zero plaintext leaks**,
  reconnect ~3.5 ms, 249 handshakes/s under congestion **[measured]**.
- **Scale:** 3/10/50-node meshes — **1 225 real PQC sessions**, unprovisioned
  identities rejected fleet-wide **[measured]**.
- **End-to-end:** a 5-node Strategic→Regional→Tactical→Legacy deployment survived
  node failure, re-tasking, quarantine and recovery with **zero cleartext
  throughout** **[measured]**.
- **Portability:** full test suite (193 tests) passes on the **ARM64 ISA**;
  byte-identical wire artifacts **[measured-emulated]**.
- **Sovereign keys:** sealed to TPM2 / PKCS#11 through the production adapter
  [tested]; physical-device acceptance [design].

All numbers reproduce from in-repo scripts and `cargo test`/`cargo bench`. The
living evidence ledger is `docs/DEFENCE_READINESS_REVIEW.md`.

## Current Technology Readiness Level

**TRL 5** — components validated in a relevant (simulated contested) environment
on commodity Linux with real kernel enforcement. The honest gaps to TRL 6 are
named, not hidden: the kTLS throughput uplift is **[design]/BLOCKED** (this
container has no kernel TLS module), native ARM64 silicon and physical TPM/HSM
benchmarking are **[design]**, and multi-host (real-network) fleet convergence is
**[design]**.

## What we are asking iDEX for

A **SPARK grant** to convert the four named `[design]` items into `[measured]`
results on representative hardware, and to run a **defence pilot**:

| Use of funds | Outcome |
|---|---|
| Independent cryptographic review | published review; protocol + implementation assured |
| Hardware validation (ARM64 silicon, physical TPM/HSM, kTLS host) | every `[design]` tag replaced by `[measured]` |
| Multi-host pilot (10→50 real nodes) | TRL-6 field-representative demonstration |
| Production hardening + accreditation docs | pilot-ready, evaluation-entry release |

## Why SYNTRIASS wins the challenge

- **Sovereign & standards-aligned** — NIST FIPS 203/204 PQC, Rust memory-safety,
  Linux-native; no foreign cryptographic dependency.
- **Migration, not rip-and-replace** — existing C4I/data-link applications become
  quantum-safe with no code change.
- **Evidence discipline** — every claim is measured or explicitly marked design;
  nothing is inflated. A jury can reproduce the numbers.
- **Defence-shaped from day one** — Strategic / Tactical / Legacy deployment
  profiles, air-gapped operation, and fail-closed-by-construction match the
  Army / Navy / Air Force / Strategic Forces operating reality.

*Full package: `docs/IDEX_SUBMISSION_MASTER.md` and the documents it indexes.*
