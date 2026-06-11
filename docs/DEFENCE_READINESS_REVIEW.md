# SYNTRIASS Overlay — Defence Readiness Review (living document)

**Purpose.** This is the committed, evidence-backed continuation of the Defence
Readiness Review. It supersedes the earlier review that existed only as a working
note: from here, every finding's status is tied to committed code, committed
tests, and reproducible commands. Reviewers (DRDO cryptographers, kernel
maintainers, red-team, procurement) can re-run every claim.

**Ground rules.** No claim without evidence. Numbers are labelled **[measured]**
(a test/benchmark here produced them), **[implemented]** (code exists and is
tested), or **[design]** (specified, not yet built). The honest-boundary sections
state explicitly what is *not* proven in the current environment.

**Scope of this revision.** This revision (a) records the two hardening
increments delivered in this branch and (b) **reassesses finding C6** in full.
The remaining findings from the original review (interception universality,
identity lifecycle, resilience/netem, sovereign/ARM, formal fail-closed proofs)
are carried forward as **Open / tracked** with their honest current status; they
are not re-detailed here beyond that status to avoid restating text that is not
yet backed by committed evidence.

---

## 1. Findings ledger

| ID | Finding (summary) | Severity | Status | Evidence |
|---|---|---|---|---|
| **C6** | Handshake-flood CPU exhaustion: PQC work performed before peer validation | High → **Low** | **Mitigated — gate on the real daemon path; per-source + global caps; validated in-process, on the wire, and against the spawned daemon** | `docs/HANDSHAKE_DOS_HARDENING.md`; `src/handshake_guard.rs`; `src/bin/daemon.rs`; `src/over_socket.rs`; `tests/handshake_dos_tests.rs`, `tests/handshake_dos_integration.rs`, `tests/chaos_orchestration.rs` |
| (PQC-2) | Long-session key-wear, no anti-replay/rekey on lossy links | Med | **Mitigated (record layer implemented + tested)** | `docs/PQC_PROTOCOL_SPEC.md §4`; `src/crypto/session.rs`; `tests/session_hardening_tests.rs` |
| C1–C5, C7+ | Universal interception, identity lifecycle, resilience (`tc netem`), sovereign/ARM, formal fail-closed (Miri/Loom/fuzz) | — | **Open / tracked** | Not runnable in the current sandbox; scoped as host-only / future increments (see §4) |

> The original review's full C-series text was a chat-only artifact. Rather than
> restate findings whose details are not yet backed by committed evidence, this
> ledger names them and marks them open. They will be detailed as each is taken
> up with real code + evidence, exactly as C6 and PQC-2 were.

---

## 2. Reassessment — Finding C6

### 2.1 Original finding

> The responder executes the expensive hybrid-PQC operations (ML-KEM
> encapsulation, X25519, **ML-DSA-65 sign + verify**) on receipt of a ClientHello,
> *before* establishing that the peer is real or return-routable. A single host
> can saturate responder CPU with asymmetric work — an asymmetric-work DoS. No
> cookie/return-routability check, no rate limiting, no replay protection on the
> admission path.

**Operational impact (original):** a low-cost flood from one or few hosts could
deny service to an entire SYNTRIASS-protected enclave by starving the responder
daemon of CPU — a critical availability failure for a tactical system whose whole
value proposition is assured communications under contested conditions.

### 2.2 Before state vs integrated state

| Aspect | **Before** (original finding) | **Before** (first increment) | **Integrated (now)** |
|---|---|---|---|
| PQC reachable without peer proof? | **Yes** — per ClientHello | No (gate object), but gate not on the wire | **No — gate runs in the daemon accept loop** |
| Cookie binding | n/a | caller-supplied `source` string | **kernel-observed peer IP** (`peer_addr().ip()`) |
| Per-source rate limit | none | yes (library) | yes, **per peer IP**, on the live path |
| Aggregate (distributed) cap | none | none | **global PQC-rate + in-flight concurrency caps** |
| Validation | n/a | in-process PQC counts | in-process **+ on-the-wire + spawned-daemon** |

### 2.3 What was implemented (integrated)

A two-phase **stateless-cookie admission gate** (`src/handshake_guard.rs`),
**wired into the live daemon** (`src/bin/daemon.rs` →
`over_socket::establish_and_bridge_gated`) for every accepted connection. Full
design in `docs/HANDSHAKE_DOS_HARDENING.md`. Key points:

- **Return-routability before PQC, on the real path.** Cookie =
  `HMAC-SHA256(rotating secret, label ‖ peer-IP ‖ issued_at ‖ nonce)`, issued
  statelessly. The daemon runs `respond()` **only** after `admit()` *and* the
  global gate both pass. **[implemented]**
- **Cookie bound to the live peer identity** — the kernel-reported peer IP, keyed
  on IP (not ip:port) so fresh ephemeral ports cannot bypass limits. **[implemented]**
- **Global PQC-work + concurrency limits** (`try_acquire_pqc`) complementing the
  per-source bucket: a single all-sources rate bucket + an in-flight cap with an
  RAII permit that releases on every exit path. Bounds a *distributed* flood.
  **[implemented]**
- **Replay resistance**: freshness window + constant-time MAC
  (`subtle::ConstantTimeEq`) + one-time consumed-tag set (pruned + capped).
- **No new dependencies** (`hmac`, `subtle` were already transitive).

### 2.4 Evidence (reproducible)

```
cargo test --lib handshake_guard                                   # 16 unit tests
cargo test --test handshake_dos_tests --test handshake_dos_integration -- --nocapture
cargo test --test chaos_orchestration                             # spawns the real daemon
```

**In-process, counting real `respond()` invocations** (**[measured]**):

| Attack | Volume | PQC invocations |
|---|---:|---:|
| Forged-cookie flood | 50 000 | **0** |
| Spoofed-source flood | 20 000 sources | **0** |
| Malformed messages | 6 000 | **0** |
| Replayed handshake | 10 000 submissions | **1** |
| Legitimate flood (rate 20/10s⁻¹) | 1 000 attempts | **20** (per-source cap) |
| **Distributed flood, 5 000 distinct sources** | 5 000 sources | **25** (= global burst) |

**On the real wire, through the gated daemon path** (**[measured]**):

| Scenario | Connections | Reached PQC | Rejected at gate |
|---|---:|---:|---|
| Genuine peers | 3 | **3** | 0 |
| Forged-cookie flood | 10 | **0** | 10 `BadMac` |
| Replayed cookie | 1 + 5 | **1** | 5 `Replay` |
| Concurrent load (global burst 5) | 40 | **5** | 35 globally shed |

Plus end-to-end against the **spawned daemon binary**
(`chaos_orchestration::daemon_context_kill_fails_closed`): real gated handshakes
complete while the daemon lives and fail closed when it is killed.

### 2.5 Residual risk and revised severity

Residual risks (detailed in `docs/HANDSHAKE_DOS_HARDENING.md §6`):

- **R1 distributed botnet flood** — the global rate + concurrency caps now bound
  *aggregate* PQC work (the responder can no longer be CPU-exhausted). Residual is
  a **fairness** concern: legitimate peers compete for the global budget under a
  large flood (they retry). Priority/allow-listing + eBPF ingress controls are
  **[design]**.
- **R2 cookie issuance is a per-packet HMAC** — ~3–4 orders of magnitude cheaper
  than the ML-DSA-65 it replaces; line-rate packet floods belong behind kernel/eBPF
  ingress controls.
- **R3 clock dependence** — uses a monotonic seconds clock that cannot run backward.
- **R4 shared-guard `Mutex`** — held only briefly, never across `await` or PQC, so
  it does not serialise the expensive work; a sharded guard is a future optimisation.
- **R5 eBPF event-source transport** — the gate covers the TCP-accept and
  fd-passing paths; the out-of-tree eBPF RingBuf transport will reuse the same
  contract when built (**[design]**).

**Revised severity: High → Low.** The asymmetric-work DoS primitive is removed on
the real execution path and validated in-process, on the wire, and against the
spawned daemon. C6 is downgraded to **Low** (residual is degraded *fairness* under
a distributed flood, not a CPU-exhaustion DoS). It is **not** marked Closed only
because the eBPF event-source transport (R5) and the botnet-fairness controls (R1)
remain to fully retire the residual — both tracked, neither a CPU-DoS.

---

## 3. Delivered hardening increments (this branch)

1. **PQC record-layer hardening (PQC-2).** Explicit sequencing, IPsec/DTLS-style
   sliding-window anti-replay, forward-secret rekey ratchet, and session
   lifecycle limits over the real handshake. Measured end-to-end at 10/20/30/45%
   loss: 100% of delivered records open exactly once, 100% of replays rejected,
   zero false accepts. See `docs/PQC_PROTOCOL_SPEC.md §4`.
2. **Handshake DoS gate (C6).** Stateless-cookie admission gate **on the live
   daemon path**, binding cookies to the kernel-observed peer IP, with per-source
   *and* global (aggregate PQC-rate + in-flight concurrency) limits. Validated
   in-process (real `respond()` counts), on the wire (gated path), and against the
   spawned daemon binary. This document, §2.

Both are pure-Rust, fully tested in-sandbox, and add no packages to the
dependency tree.

---

## 4. Honest boundary — not proven in the current environment

These require provisioned hardware/toolchains absent from this sandbox and are
tracked as host-only or future increments; they are **[design]** here and must
not be read as validated:

- **Universal eBPF interception** across glibc/musl/static/Go/containers/K8s
  (no `bpf-linker`/`tc`/CAP_BPF here).
- **`tc netem` 10/20/30/45% loss** at the kernel qdisc level (the record-layer
  loss numbers above use an in-process model, clearly labelled as such).
- **Identity lifecycle** (enrolment/rotation/revocation/expiry, TPM2/PKCS#11/HSM,
  air-gap provisioning).
- **Sovereign ARM64** hardware validation.
- **Formal fail-closed assurance** (Miri/Loom/fuzzing/property-model-checking).

---

## 5. Reproduce everything

```
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo build --release --locked
cargo test --release --locked
cargo test --test handshake_dos_tests --test handshake_dos_integration \
           --test session_hardening_tests -- --nocapture
cargo test --test chaos_orchestration     # spawns the real daemon binary
```

All gates pass in this environment at the current HEAD.
