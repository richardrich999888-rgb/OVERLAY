# SYNTRIASS — Security Remediation Report

**Internal Security Hardening and Pre-Audit Remediation.** Not an independent
audit, certification, or compliance attestation. Self-reported; "Closed" means
implemented + tested in this repository, not independently verified.

## Scope
Remediation of the Critical findings from the Internal Security Review
(`docs/PRE_AUDIT_SECURITY_REVIEW.md`, `docs/CRITICAL_FINDINGS.md`) plus the two
top kernel/egress Highs.

## Verification run (this pass)
- `cargo fmt --check` — clean.
- `cargo clippy --all-targets -- -D warnings` — clean.
- `cargo test --release --locked` — **31 suites, 229 tests, 0 failures.**
- New security tests: CR-2 fork (5), CR-3 air-gap (7 incl. fault-injection),
  CR-4 supply-chain (6), CR-1 socket-classification (4) = 22 new.
- Fault injection: `parser_fault_injection_never_panics_and_fails_closed`
  (byte-mutation + random buffers over the new on-disk parser) — no panic, all
  fail closed.
- eBPF: `policy_v2.bpf.c` (incl. new `connect6`) compiles clean for the BPF target.

## 1. Findings closed
| ID | Finding | Status | Evidence |
|---|---|---|---|
| **CR-1** | Interceptor fail-open on indeterminate socket type | **Closed [implemented][tested]** | `is_stream_socket` fail-closed; `socket_classification_tests` |
| **CR-2** | Fork-after-connect AES-GCM nonce reuse | **Closed [implemented][tested]** | fork-aware token + atfork + `is_inherited`; `cr2_nonce_reuse_tests` (real fork; reuse demonstrated + averted) |
| **CR-3** | Air-gap unauthenticated integrity (peer-key MITM) | **Core closed [implemented][tested]**; deployment wiring [design] | hybrid-signed bundles; `airgap` unit (8) + `cr3_airgap_signing_tests` (7) |
| **CR-4** | Unauthenticated install/package chain (root RCE) | **Core closed [implemented][tested]**; install wiring [design] | signed manifest + installer gate; `cr4_supply_chain_tests` (6) |

## 2. Findings remaining (open / partial)
| ID | Finding | State |
|---|---|---|
| CR-3 / CR-4 deployment | `airgap.sh`/`install.sh`/`package.sh` still use unauthenticated SHA-256; must call the new verifier | **[design]** — the secure core is tested but not yet the deployment default |
| HI-1 | IPv6/UDP egress coverage | **partial** — `connect6` [implemented, compile-verified]; live attach + `sendmsg4/6` UDP **[design]** |
| HI-2 | Kernel enforcement fails open on loader detach | **[design]** — pinning + default-deny baseline + supervision specified, not yet built |
| HI-3..HI-5 | Interceptor: no accept hook, fd-reuse TOCTOU, registry growth/dup2 | **open** |
| HI-6..HI-9 | Deploy temp-file private-seed leaks, inventory injection | **open** (low-effort, recommended next) |
| Mediums/Lows | per `docs/SECURITY_REMEDIATION_PLAN.md` | open |

## 3. New findings discovered during remediation
- **NF-1 (Low):** CR-2's `pthread_atfork` guard does not run for a **raw
  `clone()`** that bypasses the glibc wrapper; that path relies on the `getpid`
  backstop. `note_fork_in_child()` is exposed for a clone-aware wrapper. Flagged
  for external review.
- **NF-2 (Informational, confirms E-3):** the kernel `connect4/6` hook gates
  connection *establishment*, not encryption; complete egress coverage closes the
  bypass but does not make the kernel the encryption authority. Must be explicit in
  the threat model.

## 4. Security score: **6.5 / 10** (was ~4)
Two Criticals fully closed (CR-1, CR-2); two Critical cores closed with tested
fixes ready to wire (CR-3, CR-4); IPv6 program added. Held below 8 by the
un-wired deployment path (CR-3/CR-4 not yet enforced by the shipped scripts),
the open interceptor Highs, and the loader fail-open.

## 5. Pilot readiness score: **5 / 10** (was 4) — see `docs/PILOT_READINESS_REASSESSMENT.md`
## 6. Audit readiness score: **7 / 10** (was 5.5) — see `docs/AUDIT_READINESS_REASSESSMENT.md`

## 7. TRL impact
Functional **TRL 5 unchanged**. The security backlog gating a TRL-6 operational
pilot is materially reduced: the crypto-break (CR-2) is eliminated and the
trust/supply-chain Criticals have tested cores. Remaining gates to an operational
pilot: wire CR-3/CR-4 into deployment, complete HI-1 (UDP + live IPv6) and HI-2
(loader fail-closed), and commission the external cryptographic review.
