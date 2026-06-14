# SYNTRIASS Overlay — Internal Security Review / Pre-Audit Assessment

> **Status label (applies to this entire document and the companion files):**
> **Internal Security Review / Pre-Audit Assessment.** This is NOT an independent
> certification, NOT a compliance attestation, and NOT a completed audit. It is a
> first-party, adversarial code review intended to find issues *before* an external
> assessor does. Findings are the reviewer's opinion from reading the source;
> they have not been confirmed by exploitation in a production environment.

**Reviewers (roles enacted):** principal cryptographer · Rust security auditor ·
eBPF security auditor · Linux kernel security reviewer · red-team operator ·
banking security assessor · defence cybersecurity evaluator.

**Scope reviewed:** `src/` (crypto, interceptor, fd_state, fd_passing,
kernel_native, keystore, identity, handshake_guard, kinetic, profiles,
over_socket, daemon), `ebpf/c/` (connect4, policy, policy_v2 + loaders),
`deploy/` (install, package, validate-config, systemd, upgrade, rollback, airgap,
fleet), and the handshake/PQC/fleet/air-gap/fail-closed designs.

**Method:** direct line-by-line reading of the security-critical Rust (crypto
handshake, record layer, interception data path) and the eBPF C; two parallel
deep sub-reviews (FFI/interceptor; deploy shell); cross-checking documentation
claims against the actual code. **No claim in the repository's own docs was
treated as true without reading the implementation.** Passing tests, fuzzing, and
Rust's guarantees were explicitly NOT treated as proof of security.

---

## 1. Executive verdict

The cryptographic **core protocol** (hybrid X25519+ML-KEM key agreement, HMAC
mutual authentication over the provisioned secret, transcript binding, AES-256-GCM
record layer with overflow-guarded nonces, ephemeral forward secrecy) is, on
reading, **structurally sound**. The serious findings are **not** in the
primitive cryptography — they are in the **boundaries** around it:

1. the **userspace interception** layer can fail *open* (leak plaintext) and has a
   **fork→nonce-reuse** exposure;
2. the **kernel eBPF** enforcement only covers IPv4 TCP `connect` and disappears
   if the control plane dies — so the "kernel guarantees no plaintext" claim is
   **protocol-incomplete and liveness-dependent**;
3. the **air-gap / deployment** integrity is an **unauthenticated checksum** an
   active adversary can forge, which undermines the offline trust model and the
   supply chain.

**These gaps mean the platform is not ready to carry real operational traffic in a
pilot without remediation** (see `docs/PILOT_READINESS_ASSESSMENT.md`). They do
**not** invalidate the TRL-5 functional evidence; they define the security
backlog that must close before an operational pilot or external audit.

## 2. Findings by severity (totals)

| Severity | Count | Open | Fixed this pass |
|---|---:|---:|---:|
| **Critical** | 4 | 3 | 1 (CR-1) |
| **High** | 9 | 9 | 0 |
| **Medium** | 9 | 9 | 0 |
| **Low** | 8 | 8 | 0 |
| **Informational** | 7 | 7 | 0 |

One Critical (CR-1, interceptor fail-open on an indeterminate socket-type probe)
was fixed end-to-end in this pass — fix + 4 regression tests + full gate re-run +
re-classification to Low. Every other Critical/High is **OPEN** with precise
remediation in `docs/SECURITY_REMEDIATION_PLAN.md`. The remaining items were
**deliberately not patched in this pass**: they require careful design and real
kernel / multi-host / hardware validation, and shipping unvalidated changes to the
interception, kernel-enforcement, and key-distribution layers would itself be a
security risk and would violate the no-overclaiming discipline of this review.

## 3. Critical findings (summary; full detail in `docs/CRITICAL_FINDINGS.md`)

- **CR-1 [FIXED → Low] Interceptor fail-open on indeterminate socket type.**
  `is_stream_socket` (`src/interceptor.rs`) returned `false` both for "not a
  socket" and "could not determine type", and the data path then called *real
  libc* (plaintext) on `false`. A transient `getsockopt(SO_TYPE)` failure on a
  real socket leaked cleartext. **Fixed:** the probe now passes through only
  `ENOTSOCK`/`EBADF` (genuine files / already-erroring fds) and treats any other
  errno as a socket → tracked → **fail closed**. Regression tests added
  (`socket_classification_tests`).
- **CR-2 [OPEN] Fork-after-connect GCM nonce/key reuse.** The only fork defense is
  a `getpid()` equality check (`inherited_after_fork`); there is no
  `pthread_atfork` handler and no per-process nonce salt. A `clone(CLONE_VM)` /
  PID-reuse / namespace path that defeats the `getpid` check lets parent and child
  seal records under the **same key + overlapping nonce** → catastrophic AES-GCM
  failure (forgery + plaintext recovery).
- **CR-3 [OPEN] Air-gap artifact integrity is unauthenticated.** Identity exports
  and policy bundles (`deploy/airgap.sh`) carry an **unkeyed SHA-256 stored inside
  the artifact they protect**. An adversary on the sneakernet path edits the
  artifact and recomputes the hash; `import-peer` then accepts attacker-chosen
  peer **public keys** → man-in-the-middle of the entire overlay's authentication.
  The documented "fail-closed on tampered artifact" guarantee is **false against
  an active adversary**.
- **CR-4 [OPEN] Unauthenticated install/package chain (supply-chain RCE).**
  `deploy/package.sh` ships a `SHA256SUMS` inside the package; `deploy/install.sh`
  **never verifies it** and installs/runs binaries as root. Anyone who can modify
  the distributed tarball achieves root code execution on every installing host.

## 4. Protocol audit (cryptographer)

| Property | Finding | Tag |
|---|---|---|
| **Replay resistance (records)** | Sound on the hardened `SecureSession` (epoch‖seq AAD + RFC-6479-style window, window advanced only after AEAD verify). The **deployed `Direction` layer** (OOB/over_socket path) uses an implicit counter — it rejects replays but **cannot tolerate loss/reorder** (ME-3). | mixed |
| **Replay resistance (handshake)** | **Gap (ME-1):** the OOB ClientHello has no nonce/timestamp/freshness; a captured ClientHello is replayable to the responder indefinitely (responder does KEM work; attacker cannot derive keys → bounded DoS, not auth bypass). The `SessionToken` epoch that would window this is implemented but **not bound into the wire transcript** ([design] in the code's own comments). | Medium |
| **Downgrade resistance** | Sound. `suite_id` is in the HMAC, the transcript, and HKDF `info`. The OOB path is single-suite (`0x01`), not attacker-selectable, so there is no in-band downgrade vector. The interceptor's `negotiation_tests` confirm a healthy `FullPqc` responder rejects a `FallbackHello` (no MITM-forced PSK). | OK |
| **Authentication** | Sound but **symmetric** (HMAC over a shared per-pair `auth_secret`). Mutual auth holds if the secret is secret. **Trust-model caveat (ME-2):** a single node's registry compromise allows impersonation in **both** directions of that pair (KCI) — inherent to PSK auth, must be documented as the model. | OK + caveat |
| **Key confirmation** | Server tag confirms the responder to the initiator. **No explicit initiator→responder confirmation** (2-message; the responder commits keys after one round; first sealed record is implicit confirmation). Acceptable but noted (LO-1). | Low |
| **Forward secrecy** | **Present.** IKM = ephemeral X25519 ‖ ephemeral ML-KEM; `auth_secret` only authenticates and is never mixed into IKM, so its later compromise does not reveal past sessions. The intra-session rekey ratchet (`Direction::ratchet`, one-way HKDF) adds forward secrecy across epochs. The **fallback** path has no FS (documented). | OK |
| **Identity binding** | Sound. Client `own_hash` is MAC-bound and used to resolve the secret; server hash is MAC-bound and checked against `expected_server_hash`. A party cannot claim an identity without its secret. | OK |
| **Session resumption** | Not implemented (no resumption tickets) → no resumption-specific attack surface. | OK |
| **Revocation** | `PeerRegistry::revoke` makes `lookup` fail closed (revoked hash → `None`), proven by a real-handshake test. **Gaps:** revocation is node-local; no signed CRL→registry feed and no fleet propagation ([design]); a compromised node keeps talking until each peer is told to revoke it. | partial |
| **Cryptographic agility** | The full in-band path negotiates 768/1024; the OOB path is fixed to 768. No mechanism to retire a broken suite fleet-wide yet ([design]). | partial |
| **AEAD nonce safety** | Sound *within a process*: nonce = `0‖counter_BE`, overflow-guarded (`NonceExhausted` at `u64::MAX`), ephemeral per-direction keys, two directions keyed differently. **Cross-process (fork) is the exposure — see CR-2.** | mixed |
| **Fail-open conditions** | **CR-1 (fixed)** plus the interceptor class (H-1/H-2/H-3) and the eBPF class (HI-1/HI-2). | see §5/§6 |

## 5. eBPF / kernel audit

| Check | Finding | Severity |
|---|---|---|
| Policy enforcement correctness | The `connect4` decision logic (map-miss → deny, FailClosed → deny, expiry/quarantine/crypto gates) reads correctly and is fail-closed **while attached**. | OK |
| **Hook coverage / packet escape (HI-1)** | **All** programs are `SEC("cgroup/connect4")`. There is **no `connect6`** (IPv6 TCP), **no `sendmsg4/6`** (UDP), and no coverage of already-connected or non-`connect` egress. An application using IPv6 or UDP **bypasses policy entirely** → fail-open for those protocols. | **High** |
| **Liveness dependence (HI-2)** | Enforcement exists only while the cgroup program is attached. If the loader/daemon dies or is killed, the program detaches and `connect` is allowed by default → **fail open at the kernel layer**. No pinned `bpf_link` or watchdog re-attach. | **High** |
| Kernel/userspace trust boundary (E-3) | The `connect4` hook gates connection *establishment* by posture; it does **not** encrypt. Encryption is the userspace interceptor. So a kernel-**allowed** connection is **not guaranteed encrypted** — the kernel and the crypto are decoupled. This materially weakens the "kernel guarantees no plaintext" framing. | Informational (architectural) |
| Map isolation / privilege | Maps are held by the root loader's fds and are not pinned world-writable; an unprivileged process cannot write them without `CAP_BPF`/the fd. No finding, but pinning permissions are undocumented (LO-2). | Low |
| Privilege requirements | Loading requires root / `CAP_BPF`+`CAP_SYS_ADMIN`+cgroup2 — appropriate. | OK |
| Verifier safety | Programs pass the kernel verifier; use no CO-RE/arch-specific helpers. | OK |
| Race conditions | The map read on each `connect` is a single lookup; userspace updates are atomic map writes. No TOCTOU in the kernel path itself. | OK |

## 6. Code audit (Rust memory-safety / concurrency)

| Check | Finding | Severity |
|---|---|---|
| Integer overflow | The historically fuzzer-found epoch overflow is fixed; AEAD counter overflow is guarded. `n as usize` slice indices are currently in-bounds but lack defensive clamps (ME / LO). | Low |
| Panic paths | An FFI panic shield (`catch_unwind`) wraps the hooks; **its correctness depends on the release `cdylib` being built `panic = "unwind"`** — verify in `Cargo.toml`, else the shield is void (LO-3). | Low |
| Unsafe blocks (87) | The interposition/fd code is the concentration. `transmute_copy` of `dlsym` pointers is sound only for fn-pointer `T` (LO-4). `inotify_event` decode uses `read_unaligned` correctly (verified). | Low |
| Memory-safety in the data path | **H-2 (fd-number-reuse TOCTOU)** and **M-3 (iovec double-read)** are the real ones: in-flight syscalls can target a recycled fd / re-read a racing iovec. | High / Medium |
| Concurrency / locks | Global registry under `Mutex`; lock-poison recovery via `into_inner()` is asserted-safe but not proven for a panic mid-`HashMap::insert` (LO-5). | Low |
| Lock poisoning | See above; no deadlock found in the reviewed paths (Loom covers the kinetic/session paths, not the interceptor registry). | Low |
| TOCTOU | H-2 (fd registry) and the deploy temp-file races (HI-7) are the notable ones. | High |
| Error handling | Predominantly `Result`-based and fail-closed; the fixed CR-1 was the dangerous exception. 283 `unwrap/expect/panic` sites exist in non-test code — most are behind the FFI shield or on provably-infallible paths, but this is a large surface to keep audited (Informational). | Info |
| Resource exhaustion | **H-3 (unbounded fd-registry growth; dup2/dup3 not interposed).** | High |

## 7. Operational audit

| Check | Finding |
|---|---|
| Daemon crash handling | The overlay fails closed on daemon death for *interposed* flows; but the **kernel** eBPF enforcement fails *open* on loader death (HI-2), and a non-interposed protocol (IPv6/UDP, HI-1) is unprotected regardless. |
| CPU starvation | Handled in prior measured work (battlefield suite); not re-examined here. |
| Memory exhaustion | The interceptor registry can grow unbounded (H-3); per-fd buffers are capped. |
| Network degradation | The **deployed `Direction` record layer desyncs on packet loss (ME-3)** — the loss-tolerant `SecureSession` is a separate layer not used on the OOB/over_socket path. This contradicts the battlefield-resilience posture for that path and should be reconciled. |
| Reconnect / recovery | Kinetic supervisor recovery is measured and sound (prior work); revocation/quarantine fleet propagation remains [design]. |

## 8. Documentation-vs-code integrity check

A first-party review must also flag where the marketing/readiness docs overstate
the code:

- **"Kernel-enforced no-plaintext leak even under host compromise"** — partially
  true: the kernel gates `connect4` only, does not encrypt, fails open on
  detach, and does not cover IPv6/UDP (HI-1/HI-2/E-3). The claim should be
  qualified.
- **"Air-gap: tampered artifact refused (fail closed)"** — **false** against an
  active adversary (CR-3); true only against accidental corruption.
- **"No plaintext state is representable"** — accurate for the *posture/state
  machine* (compiler-enforced), but plaintext can still reach the wire via the
  interceptor fail-open class and the eBPF coverage gap. The structural guarantee
  is about *modes*, not about *every egress path*.

These should be corrected in the readiness documents before external review (see
`docs/AUDIT_READINESS_ASSESSMENT.md`).

## 9. Items requiring external independent review

- Independent cryptographic review of the OOB protocol (replay/KCI/key-confirmation
  analysis, formal or semi-formal), the HKDF transcript binding, and the fallback
  PSK path.
- Independent kernel/eBPF review of complete egress coverage and the
  fail-open-on-detach behaviour.
- Independent supply-chain / air-gap signing design review (CR-3/CR-4).
- Side-channel evaluation of the constant-time paths on real hardware.

## 10. Cross-references

- `docs/CRITICAL_FINDINGS.md` — Critical + High, full detail.
- `docs/SECURITY_REMEDIATION_PLAN.md` — per-finding fix, status, effort, owner.
- `docs/PILOT_READINESS_ASSESSMENT.md` — pilot gate + score.
- `docs/AUDIT_READINESS_ASSESSMENT.md` — external-audit gate + score.
