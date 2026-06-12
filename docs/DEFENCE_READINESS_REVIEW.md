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
| **FC-1** | Fail-closed assurance gap: no automated proof of no-cleartext / no-panic / concurrency safety; 85/86 `unsafe` blocks undocumented; a misaligned-reference UB in the config watcher | High → **Low** | **Mitigated + validated here: property + leakage + concurrency proof, panic-path & unsafe audit (1 UB bug fixed), and Miri + Loom + cargo-fuzz all run on a nightly toolchain** | `docs/FAIL_CLOSED_ASSURANCE.md`; `tests/fail_closed_properties.rs`, `tests/concurrency_stress.rs`, `tests/leakage_analysis.rs`, `tests/loom_model.rs`; `scripts/run_miri.sh`, `fuzz/`; `src/lib.rs` (`#![deny(unused_must_use)]`) |
| **IL-1** | No identity lifecycle: peer keys statically pinned, never enrolled/rotated/revoked/expired | High → **Low** | **Mitigated: hybrid-PQC credential lifecycle — enrollment+PoP, issuance, scheduled & emergency rotation, renewal, CRL revocation with monotonic propagation, expiry, lost-key/compromised-node recovery, and offline/air-gap provisioning — 28 tests + benchmarks, shown driving the real handshake; TPM2/PKCS#11/HSM evaluated as design with infra plan** | `docs/IDENTITY_LIFECYCLE.md`, `docs/OFFLINE_PROVISIONING.md`; `src/identity.rs`; `tests/identity_lifecycle_tests.rs`; `benches/identity_benchmarks.rs` |
| **C1** | LD_PRELOAD interception is incomplete (static/Go/musl/direct-syscall bypass it) | High → **Low** | **Replaced with a kernel `cgroup/connect4` eBPF data plane, built+loaded+attached+measured: 7/7 runtimes intercepted incl. the 4 LD_PRELOAD blind spots; fail-closed deny enforced (EPERM)** | `docs/UNIVERSAL_INTERCEPTION.md`; `ebpf/c/`, `ebpf/COVERAGE_REPORT.txt`; `scripts/ebpf_coverage_validate.sh` |
| **KS-1** | File-based key storage: raw seeds on disk, no hardware protection | High → **Low–Medium** | **Backend-agnostic key-protection layer: software (AES-GCM) + TPM2 + PKCS#11/HSM. Software fully tested; TPM (swtpm) and PKCS#11 (SoftHSM2) backends validated end-to-end through the real Rust adapter against software substitutes — incl. sealed-to-hardware (a different TPM can't unseal). Physical-device acceptance = design** | `docs/KEY_STORAGE_ARCHITECTURE.md`, `docs/TPM_INTEGRATION.md`, `docs/HSM_INTEGRATION.md`; `src/keystore.rs`; `tests/keystore_external_tests.rs`; `scripts/keystore/` |
| **C2** | Resilience under degraded network unproven | Med → **Low–Medium** | **Measured: loss ladder 10/20/30/45% (record channel — delivery/goodput/latency/replay, 0 plaintext leaks), handshake success-rate floor, reconnect ~3.5ms, CPU-starvation 30/30, congestion 249 hs/s, daemon-crash + mem-exhaustion fail-closed. Real `tc netem` UNAVAILABLE here (no qdisc layer) — documented + host-side plan** | `docs/BATTLEFIELD_RESILIENCE.md`, `docs/NETEM_RESULTS.md`, `docs/RECOVERY_ANALYSIS.md`; `tests/battlefield_resilience.rs`, `tests/chaos_orchestration.rs`; `scripts/netem_validate.sh` |
| C3–C5, C7 | Sovereign/ARM hardware, et al. | — | **Open / tracked** | host-only / future increments (see §4) |

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

## 2A. Reassessment — Finding FC-1 (fail-closed assurance)

**Previous state.** The platform's core promise — *never emit plaintext, never
crash on adversarial input, fail closed on every error* — rested on hand-review
and scattered unit tests. There was **no automated proof** of the no-cleartext /
no-panic invariants under adversarial input or concurrency, and **85 of 86
`unsafe` blocks carried no `// SAFETY:` justification**. A single fail-open parser
bug or an unrejected tamper would defeat the entire mission.

**Current state.** The load-bearing invariants are now under automated, seeded,
reproducible proof, the security-critical v2 `unsafe` is documented, and a
fail-open-class lint is enforced crate-wide:

- **No-cleartext + tamper + parser robustness** (`tests/fail_closed_properties.rs`).
- **Concurrency safety** on the real shared guard (`tests/concurrency_stress.rs`).
- **`#![deny(unused_must_use)]`** crate-wide — a swallowed seal/close/teardown
  error (a fail-*open* bug) is now a compile error; the tree is clean under it.
- **Unsafe audit** (`docs/FAIL_CLOSED_VALIDATION.md §5`): all 86 blocks classified
  with their fail-closed property; SCM_RIGHTS fd-passing + the received-fd adoption
  annotated inline.

**Evidence generated** (**[measured]**, this run):

| Invariant | Volume | Result |
|---|---:|---|
| No cleartext canary (fallback + PQC, both suites) | 21 000 records | **0 leaks** |
| Tamper ⇒ fail closed | 20 000 tampered records | **0 fail-open** |
| Parsers never panic / leak (4 parsers) | 50 000 random inputs | **0 panics, 0 leaks** |
| Anti-replay never double-accepts | 400 000 ops | **0 double-accepts** |
| Cookie no false-accept | ~20 000 mutations | **0 false-accepts** |
| Concurrency cap never exceeded | 16 threads, cap 4, 75 664 acquisitions | **max in-flight = 4** |
| No deadlock / no slot leak | 12 threads × 5 000 | **final in-flight = 0** |
| Poisoned guard | production `.lock()` pattern | **fail-closed error, no panic** |

**Tooling update — now run here.** A nightly toolchain, `miri`, `loom`, and
`cargo-fuzz` were obtained and **executed in this environment** (the earlier
"blocked-on-nightly" boundary is retired):
- **Miri**: 12 pure-logic tests, **0 undefined behaviour** (after fixing the
  `fd_state.rs` misaligned-reference UB the audit surfaced).
- **Loom**: exhaustive interleaving proof of the PQC-permit cap (3 tests incl. a
  TOCTOU negative control that Loom correctly catches), **0.65 s**.
- **cargo-fuzz**: four libFuzzer targets over the parsers + responder (ASan).
  ~10.8M execs on the parser targets clean; **found and fixed a real fail-open
  bug** — an integer-overflow panic in `SecureSession::open` on a record whose
  attacker-controlled epoch was `0xFFFF_FFFF` (regression-tested, re-fuzzed clean).
Full report: `docs/FAIL_CLOSED_ASSURANCE.md`.

**Readiness impact.** FC-1 moves **High → Low**. The fail-open and
crash-on-input failure modes are disproven across hundreds of thousands of
adversarial inputs, exhaustive concurrency interleavings, and a clean Miri UB
pass; a real UB bug was found and fixed. Residual is the absence of a *nightly CI
lane* to run Miri/Loom/fuzz per-PR (R2), not an unaddressed code weakness.

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
3. **Fail-closed assurance (FC-1).** Automated property + concurrency proof of the
   no-cleartext / no-panic / cap-never-exceeded invariants, unsafe-code audit, and
   `#![deny(unused_must_use)]` lint hardening; Miri + Loom + cargo-fuzz run on a
   nightly toolchain (2 real bugs found + fixed). This document, §2A.
4. **Identity lifecycle (IL-1).** Hybrid-PQC credential lifecycle — enrollment with
   proof-of-possession, issuance, **scheduled (zero-downtime) and emergency
   rotation**, **renewal**, **CRL revocation with monotonic rollback-proof
   propagation**, expiry, **lost-key/compromised-node recovery (epoch-floor
   supersession)**, and offline/air-gap provisioning — 21 unit + 7 integration
   tests + benchmarks, shown producing the peer keys that drive the real handshake.
   TPM2/PKCS#11/HSM evaluated behind a `HybridSigner` trait with an infra-gated
   validation plan and the honest PQC caveat (hardware protects the classical key;
   ML-DSA stays software-side until PQC-capable HSMs ship).
   `docs/IDENTITY_LIFECYCLE.md`, `docs/OFFLINE_PROVISIONING.md`.

5. **Universal interception (C1).** A kernel `cgroup/connect4` eBPF data plane
   replacing LD_PRELOAD — built, loaded, attached, and **measured** on a BPF-capable
   host (kernel 6.18): one program intercepted glibc/static-glibc/Go/Rust/
   rust-musl/direct-syscall/python (7/7, incl. the 4 cases LD_PRELOAD cannot see)
   and enforced a fail-closed `EPERM` deny. `docs/UNIVERSAL_INTERCEPTION.md`,
   `ebpf/COVERAGE_REPORT.txt`.
6. **Sovereign key storage (KS-1).** A backend-agnostic key-protection layer
   (`KeyProtector` trait + `SealedKeystore`): software (AES-256-GCM under a
   passphrase KEK, 10 tests) plus TPM 2.0 and PKCS#11/HSM backends. The external
   backends were validated **end-to-end through the real Rust adapter** against
   `swtpm` and SoftHSM2 — sealing the hybrid identity seeds, transporting them,
   and unsealing to reconstruct the signer; a different TPM cannot unseal
   (sealed-to-hardware). Physical-device acceptance is `[design]`.
   `docs/KEY_STORAGE_ARCHITECTURE.md`, `docs/TPM_INTEGRATION.md`, `docs/HSM_INTEGRATION.md`.

7. **Battlefield resilience (C2).** Measured behaviour under degraded conditions:
   the loss ladder (10/20/30/45 %) over the real record channel (delivery/goodput/
   latency/replay-rejection, **0 plaintext leaks**), handshake success-rate floor,
   reconnect ~3.5 ms with fail-closed drop handling, CPU-starvation (30/30
   complete), congestion (249 hs/s), and daemon-crash + memory-exhaustion
   fail-closed (against the spawned daemon). **Real `tc netem` is unavailable in
   this environment** (the kernel has no traffic-control qdisc layer) — documented
   precisely with a runnable host-side plan (`scripts/netem_validate.sh`); the
   impairment here is a userspace model over the real bytes, tagged as such.
   `docs/BATTLEFIELD_RESILIENCE.md`, `docs/NETEM_RESULTS.md`, `docs/RECOVERY_ANALYSIS.md`.

The Rust crate is pure-Rust and adds no packages to the main dependency tree; the
eBPF data plane is out-of-tree C+libbpf (built by clang, not part of `cargo build`).

---

## 4. Honest boundary — not proven in the current environment

These require provisioned hardware/toolchains absent from this sandbox and are
tracked as host-only or future increments; they are **[design]** here and must
not be read as validated:

- **eBPF interception on Kubernetes / IPv6 / UDP.** The `cgroup/connect4` data
  plane is **measured** for TCP IPv4 across 7 runtimes on a single host (C1, no
  longer on this list for the host case). Still **[design]**: per-pod K8s attach,
  `connect6` (IPv6), `sendmsg4` (UDP), and a privileged BPF CI lane
  (`docs/UNIVERSAL_INTERCEPTION.md §5`).
- **Kernel `tc netem`** at the qdisc level: this environment has **no qdisc layer
  at all** (verified — `scripts/netem_validate.sh`), so the resilience loss ladder
  (C2) uses a userspace impairment model over the real bytes, clearly tagged; the
  host-side netem plan is in `docs/NETEM_RESULTS.md`.
- **Sovereign ARM64** hardware validation.
- **Hardware-backed key storage on a PHYSICAL device** (a real TPM chip / FIPS
  HSM). The TPM2 and PKCS#11 backends are **validated against software substitutes**
  (`swtpm`, SoftHSM2) end-to-end through the real Rust adapter (KS-1); a physical-
  device acceptance test is `[design]` (`docs/TPM_INTEGRATION.md §5`,
  `docs/HSM_INTEGRATION.md §5`). The ML-DSA key stays software-resident until
  PQC-capable HSMs ship.

> Note: Miri / Loom / cargo-fuzz (FC-1) are **no longer** on this list — they were
> run here on a nightly toolchain (see §2A and `docs/FAIL_CLOSED_ASSURANCE.md`).
> The remaining gap is a *nightly CI lane* to run them per-PR, not the tools.
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
cargo test --test fail_closed_properties --test concurrency_stress \
           --test leakage_analysis -- --nocapture
cargo test --lib identity --lib keystore --test identity_lifecycle_tests -- --nocapture
sudo bash scripts/keystore/validate.sh        # TPM (swtpm) + PKCS#11 (SoftHSM2)
cargo test --test chaos_orchestration     # spawns the real daemon binary
cargo test --release --test battlefield_resilience -- --nocapture --test-threads=1
bash scripts/netem_validate.sh            # real netem where available; else host-side plan
# nightly (validated here): scripts/run_miri.sh ; cargo test --test loom_model --release ;
#                           cargo +nightly fuzz run cookie_parse -- -max_total_time=60
```

All gates pass in this environment at the current HEAD.
