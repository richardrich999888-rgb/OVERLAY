# 8. Residual Risk Report

Tags per `00_INDEX.md`. This report states, without softening, what remains
**unproven or at risk** after the hardening programme. Nothing here is a known
defect; all are **integration / fielded-environment** gaps with a defined
close-out. They are excluded from TRL/readiness credit.

## 8.1 Residual risks, by theme

### A. Fielded-environment validation (the dominant residual)

| ID | Residual | Why it matters | Close-out | Tag |
|---|---|---|---|---|
| RR-1 | **K8s / multi-node interception** unproven | The measured eBPF coverage is single-host; production is per-pod across a cluster | Cluster + per-pod cgroup attach (DaemonSet/CNI, Cilium model) | [design] |
| RR-2 | **ARM64 / sovereign** unproven | Target may be A64FX/Grace/Altra; only x86_64 run here | Build + full suite + eBPF on ARM64 host | [design] |
| RR-3 | **Real `tc netem`** resilience unproven | Loss ladder is an in-process model, not a kernel qdisc | netem lab @ 10/20/30/45 % loss + jitter/reorder | [design] |
| RR-4 | **kTLS in-kernel round-trip** not exercised | Sandbox lacks the TLS ULP | kTLS-enabled kernel test lane | [design] |
| RR-5 | **Integrated demo** (eBPF→daemon→PQC→kTLS, cross-host) absent | Subsystems validated individually | 2+ host end-to-end demonstration | [design] |

### B. Cryptographic / hardware

| ID | Residual | Why it matters | Close-out | Tag |
|---|---|---|---|---|
| RR-6 | **Hardware key protection** absent; ML-DSA key software-resident | Extraction resistance; TPM/HSM lack ML-DSA today | `swtpm`/SoftHSM2 → real TPM/HSM; PQC-capable HSM for ML-DSA | [design] |
| RR-7 | **End-to-end constant-time** audit incomplete | Timing side channels in the responder | Timing-adversary review + `dudect`-style tests | [design] |
| RR-8 | **IPv6 / UDP egress** not intercepted | `connect4`/TCP only | `connect6` + `sendmsg4` programs (symmetric) | [design] |
| RR-9 | **No formal proofs** | Assurance is property/fuzz/Loom/Miri, not machine-checked | Protocol model in a proof assistant (e.g. ProVerif/Tamarin) | [future] |

### C. Process / independent assurance

| ID | Residual | Why it matters | Close-out | Tag |
|---|---|---|---|---|
| RR-10 | **Assurance not gate-enforced in CI** | Miri/Loom/fuzz/eBPF run on demand, not per-PR | Privileged BPF + nightly CI lanes | [design] |
| RR-11 | **No independent red-team / interop** | External validation strengthens credibility | Commission red-team + third-party interop | [future] |
| RR-12 | **LD_PRELOAD fallback retained** | A libc-only path still exists (defence-in-depth) | Document as non-primary; deprecate once eBPF is the deployment default | [implemented] (accepted) |

### D. Operational

| ID | Residual | Why it matters | Close-out | Tag |
|---|---|---|---|---|
| RR-13 | **eBPF attach scope = cgroup** | Processes outside the attached cgroup are unseen | Attach at the correct root (host/pod); document SOP | [design] |
| RR-14 | **Privilege required** for the agent | The enforcement agent is privileged | Deploy with least-privilege capabilities, attested | [design] |
| RR-15 | **CRL distribution to air-gap** is policy, not code | Revocation latency bounded by courier cadence | Define CRL cadence / `next_update` sizing SOP | [design] |
| RR-16 | **Kernel dependency** (cgroup v2 + `CGROUP_SOCK_ADDR` ≥4.17) | Older/locked kernels can't run the data plane | Validate target kernel; LD_PRELOAD as the libc-only fallback | [implemented]/[design] |

## 8.2 What is NOT a residual (retired with evidence)

To be explicit for reviewers, the following were *core* risks and are **closed
with evidence in this environment** (not residual):

- Interception universality (LD_PRELOAD blind spots) — **measured** 7/7. [measured]
- Fail-open / crash-on-input — **measured** (property + fuzz + Miri; bug fixed). [measured]
- Asymmetric-work DoS — **measured** (gate on live path; 0 PQC under floods). [measured]
- Replay / key-wear on lossy links — **measured** loss ladder. [measured]
- No identity lifecycle — **tested** full software lifecycle driving the handshake. [tested]

## 8.3 Bottom line

The residual is **deployment and fielded-environment risk**, honestly enumerated
and each with a concrete, infrastructure-bounded close-out. There is **no open
known defect** in the validated subsystems. This is the expected posture at the
TRL 5 → 6 boundary: the technology works and is evidenced; what remains is
demonstrating it integrated, on the target hardware, in the target environment,
under independent scrutiny.
