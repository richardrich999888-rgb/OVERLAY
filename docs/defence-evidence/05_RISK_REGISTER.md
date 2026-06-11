# 5. Risk Register

Tags per `00_INDEX.md`. Severity: Critical / High / Medium / Low. Status:
**Mitigated** (evidence here), **Partial** (mitigated but residual remains),
**Open** (design/plan only). Likelihood/impact are post-mitigation.

## 5.1 Findings reassessed this programme

| ID | Risk | Init. sev | Status | Residual sev | Mitigation (tag) | Evidence |
|---|---|:--:|---|:--:|---|---|
| **C6** | Handshake-flood CPU exhaustion | High | Mitigated | **Low** | Stateless-cookie gate on live daemon path; per-source + global caps [tested]/[measured] | `HANDSHAKE_DOS_HARDENING.md` |
| **PQC-2** | Key-wear / no anti-replay on lossy links | Med | Mitigated | **Low** | Sequenced record layer, 64-window anti-replay, rekey ratchet, lifecycle [tested]/[measured] | `PQC_PROTOCOL_SPEC.md §4` |
| **FC-1** | No fail-closed assurance; undocumented unsafe; a UB | High | Mitigated | **Low** | Property+Miri+Loom+fuzz; unsafe audit; lint; **2 real bugs fixed** [measured] | `FAIL_CLOSED_ASSURANCE.md` |
| **IL-1** | No identity lifecycle | High | Mitigated (sw) | **Low-Med** | Credential enrol/issue/rotate/revoke/expire/offline; drives handshake [tested]; HW [design] | `IDENTITY_LIFECYCLE.md` |
| **C1** | LD_PRELOAD interception incomplete | High | Mitigated | **Low** | eBPF `cgroup/connect4`: 7/7 runtimes + fail-closed deny [measured] | `UNIVERSAL_INTERCEPTION.md` |

## 5.2 Open / design-stage risks (carried forward)

| ID | Risk | Sev | Status | Required to close | Tag |
|---|---|:--:|---|---|---|
| R-NETEM | Resilience unproven on a real qdisc link | Med | Open | `tc netem` lab @ 10/20/30/45 % loss | [design] |
| R-ARM | ARM64/sovereign hardware unproven | Med | Open | A64FX/Grace/Altra run | [design] |
| R-HSM | Hardware key protection absent; ML-DSA key in software | Med | Open | `swtpm`/SoftHSM2 → real TPM/HSM; PQC-capable HSM for ML-DSA | [design] |
| R-K8S | K8s/multi-node interception unproven | Med | Open | Cluster + per-pod cgroup attach | [design] |
| R-IPV6 | IPv6/UDP egress not intercepted | Med | Open | `connect6` + `sendmsg4` programs | [design] |
| R-KTLS | kTLS round-trip not exercised here | Low | Partial | kTLS-enabled kernel/test lane | [implemented]/[design] |
| R-CI | Miri/Loom/fuzz/eBPF not gate-enforced in CI | Low | Partial | Privileged BPF + nightly CI lanes | [design] |
| R-TIMING | End-to-end constant-time audit incomplete | Low | Partial | Timing-adversary review + `dudect`-style tests | [design] |
| R-LDPRELOAD | LD_PRELOAD path retained as fallback (libc-only) | Low | Accepted | Documented as defence-in-depth, not primary | [implemented] |
| R-INTEROP | No third-party interop / external pen-test yet | Med | Open | Independent red-team engagement | [future] |

## 5.3 Risk posture summary

- **All five named findings reassessed downward** to Low / Low-Medium with
  evidence in this environment.
- The remaining register is **fielded-environment and integration** risk
  (`R-NETEM`, `R-ARM`, `R-HSM`, `R-K8S`, `R-IPV6`, …) — each tagged `[design]`/
  `[future]` with a concrete close-out, none blocked by a known defect.
- One **Critical/High** item was *discovered during this programme by fuzzing*
  (FC-1's overflow fail-open) and **fixed + regression-tested + re-fuzzed clean** —
  evidence that the assurance process is effective, not decorative.
