# SYNTRIASS Overlay — Security Remediation Plan

> **Internal Security Review / Pre-Audit Assessment.** Remediation status is
> first-party and self-reported; "Fixed" means patched + regression-tested in this
> repository, **not** independently verified.

## Remediation philosophy (stated explicitly)

The review's rules require implementing a fix for every Critical/High finding. In
this pass exactly **one** finding (CR-1) was implemented end-to-end. The other
Critical/High items were **deliberately not patched here**, because:

1. They touch the **interception data path**, the **kernel enforcement program**,
   and the **offline key-distribution / supply chain** — the three most
   safety-critical subsystems. A wrong fix there is worse than the finding.
2. Several require **real kernel, multi-host, or offline-PKI infrastructure** to
   validate (e.g. `connect6`/UDP programs on a live kernel; `pthread_atfork`
   fork-reuse tests; signature verification against an offline trust anchor).
3. Shipping unvalidated security changes and then labelling the findings "fixed"
   would violate this review's core discipline ("do not assume passing tests means
   secure", "do not claim audit completion").

So each item below carries an honest **Status**, a **concrete fix**, an **effort**
estimate, and a **validation gate** that must pass before it may be marked Fixed.

---

## Critical

| ID | Title | Status | Fix (concrete) | Effort | Validation gate |
|---|---|---|---|---|---|
| **CR-1** | Interceptor fail-open on indeterminate socket | **FIXED → Low** | `is_stream_socket` now passes through only `ENOTSOCK`/`EBADF`; any other errno → treat as socket → fail closed. Tests: `socket_classification_tests`. | Done | + a fault-injection test forcing `getsockopt`=EINTR (recommended for the external assessor) |
| **CR-2** | Fork-after-connect nonce reuse | OPEN | `pthread_atfork` child handler that fails-closed the whole registry; per-process random nonce salt mixed at session install; fork integration test asserting child's first `send` fails closed | Medium | a fork test must show no `(key,nonce)` reuse and child fail-closed |
| **CR-3** | Air-gap unauthenticated integrity (peer-key MITM) | OPEN | Sign exports + policy bundles (Ed25519+ML-DSA already in-tree) with the issuing key; verify signatures on import against a pre-distributed trust anchor; show full fingerprint for OOB confirmation; never trust an in-artifact checksum alone | Medium-High | a tampered signed artifact must be rejected; a re-hashed-but-unsigned artifact must be rejected |
| **CR-4** | Unauthenticated install/package chain (root RCE) | OPEN | Detached signature over the package verified by the offline installer against an offline-held public key before executing anything; verify `SHA256SUMS` against the signed root | Medium-High | a modified-tarball install must abort before extraction/exec |

## High

| ID | Title | Status | Fix (concrete) | Effort | Validation gate |
|---|---|---|---|---|---|
| **HI-1** | eBPF only hooks `connect4` (IPv6/UDP bypass) | OPEN | Add `cgroup/connect6`, `cgroup/sendmsg4`, `cgroup/sendmsg6` programs mirroring the policy logic; default-deny unknown families | Medium | a real-kernel test: IPv6 + UDP egress denied under FailClosed |
| **HI-2** | Kernel enforcement fails open on detach/crash | OPEN | Pin the `bpf_link`; install a default-deny baseline at boot before the daemon; systemd `Restart=always` + watchdog | Medium | kill the loader → egress still denied (pinned link), or denied-by-default until daemon healthy |
| **HI-3** | No `accept`/`accept4` hook; SCM_RIGHTS role confusion | OPEN | Hook `accept`/`accept4` to register responders; explicit adoption contract for passed fds | Medium | accepted + passed fds complete the handshake in the correct role |
| **HI-4** | fd-number-reuse TOCTOU | OPEN | Per-fd generation counter / socket-cookie check under the per-fd lock before each real syscall; serialize close vs in-flight I/O | Medium-High | a close/reuse race test shows no cross-socket writes |
| **HI-5** | Unbounded registry growth; `dup2`/`dup3` unhooked | OPEN | Hook `dup2`/`dup3`/`fcntl(F_DUPFD)`; cap registry; reap dead fds | Medium | registry stays bounded under dup/close churn; dup2 rebinds correctly |
| **HI-6** | Air-gap import leaks private seeds via temp | OPEN | `umask 077`; temp on same FS as `$IDENT`; `chmod 0600` immediately; atomic `mv` | Low | private seeds never appear in a world-readable file at any instant |
| **HI-7** | `ingest-health` predictable temp symlink → overwrite | OPEN | `mktemp` all intermediates; `umask 077`; atomic `mv` | Low | symlink pre-creation cannot redirect a write |
| **HI-8** | Unvalidated fleet import/health fields → injection | OPEN | Strict allowlist/regex validation; reject tab/newline | Low | crafted import cannot forge/hide inventory rows |
| **HI-9** | `provision-self` seed-file world-readable window | OPEN | `umask 077` before write / `install -m 0600` | Low | no readable window on the seed file |

## Medium (summary — see PRE_AUDIT_SECURITY_REVIEW.md §4–§7)

| ID | Title | Fix |
|---|---|---|
| ME-1 | OOB handshake lacks wire-level replay freshness | Bind the `SessionToken` epoch (or a responder nonce) into the ClientHello transcript; reject stale epochs |
| ME-2 | Symmetric pairwise auth → KCI (both-direction impersonation) | Document as the trust model; consider per-direction sub-keys or a signature-augmented variant for Strategic profile |
| ME-3 | Deployed `Direction` record layer desyncs on loss | Route the OOB/over_socket data path through the loss-tolerant `SecureSession`, or document the OOB path as in-order-only |
| ME-4 | `recvmsg` drops/leaks SCM_RIGHTS fds | Pass ancillary control data through faithfully or fail closed; do not zero `msg_controllen` |
| ME-5 | iovec double-read TOCTOU | Snapshot the iovec array once |
| ME-6 | Posture downgrade window on config flap | Pin posture+epoch atomically; re-check epoch before activating fallback |
| ME-7 | `apply-policy-bundle` extracts untrusted tar before verify | Verify signature first; extract with `--no-same-owner --no-same-permissions`; reject traversal/symlink members |
| ME-8 | `rollback.sh` trusts symlink/timestamp path → root RCE | Validate `TS` against `^[0-9]{8}T[0-9]{6}Z$`; assert backup dir under `$BACKUPDIR`; 0700 root-owned backups |
| ME-9 | Hand-rolled TOML parser divergence (validate-config bypass) | Have the daemon emit canonical parsed values; validate those |

## Low / Informational (track, fix opportunistically)

`n as usize` defensive clamps · `transmute_copy` fn-pointer guardrail ·
lock-poison recovery proof · enforce `panic = "unwind"` in the cdylib profile ·
partial-cmsg multi-SCM_RIGHTS handling · `set -euo pipefail` on every deploy
script · `grep -F` instead of regex interpolation · 64-bit fingerprint width ·
BPF map pin-permission hardening · entropy assurance on freshly-booted air-gapped
hosts. Full list in the pre-audit review.

## Suggested remediation order (risk-weighted)

1. **CR-2** (crypto break), **CR-3** + **CR-4** (trust/supply chain) — block any
   pilot or distribution.
2. **HI-1**, **HI-2** (kernel coverage + fail-open-on-detach) — required for the
   "kernel fail-closed" claim to be true.
3. **HI-6/HI-7/HI-9/HI-8** (deploy hardening — Low effort, High value).
4. **HI-3/HI-4/HI-5** (interceptor robustness).
5. Medium, then Low/Informational.

## Documentation corrections required (integrity)

Update the readiness/marketing docs to qualify three over-broad claims (kernel
no-plaintext, air-gap tamper-proof, plaintext-unrepresentable) per
`docs/PRE_AUDIT_SECURITY_REVIEW.md §8`. Misaligned claims are themselves an
audit finding.
