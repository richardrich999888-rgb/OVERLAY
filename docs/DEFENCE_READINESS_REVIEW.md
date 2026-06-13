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
| **PERF-1** | Runtime handshake carries ~10.5 KB ML-DSA pubkey+sig every connection; 13 KB / ~1.85 ms | High → **Low** | **Out-of-band identity: IdentityKeyHash + HMAC capability + peer registry/cache; ML-DSA moved to one-time provisioning. MEASURED: handshake 13050→2464 B (81.1%), 1846→328 us (82.2%), 0 ML-DSA on the wire; mutual-auth + fail-closed preserved (7 tests)** | `docs/OUT_OF_BAND_IDENTITY.md`; `src/crypto/oob.rs`, `src/crypto/generic.rs`; `benches/oob_benchmarks.rs` |
| **PERF-2** | Userspace record relay caps the data plane at 12.8–15.5% of line rate | Med → **Med (partial)** | **Secret bridge done + tested: kTLS keys derived from the PQC handshake (peer-agreement verified), packed into the kernel crypto_info, TLS_TX/RX install code, fail-closed-no-ULP. Throughput improvement BLOCKED here (no TLS ULP) — host-side plan + defensible recommended target (≥28% line, ~2×)** | `docs/KTLS_INTEGRATION.md`; `src/kernel_native.rs`; `tests/ktls_secret_bridge_tests.rs`, `tests/ktls_roundtrip.rs` |
| **PERF-3** | eBPF state management was a static scaffold, not operational policy | Med → **Low** | **Production cgroup/connect4 policy engine driven by live BPF maps (operation_mode/fallback/session_state) — MEASURED on kernel 6.18: posture map updates 1–3 µs, kernel ALLOWs under FullPqc and DENYs (EPERM) under FailClosed, session_state distributed kernel→userspace; fail-closed preserved** | `docs/EBPF_POLICY_ENGINE.md`; `ebpf/c/policy.bpf.c`, `ebpf/c/policy_loader.c`, `ebpf/POLICY_REPORT.txt`; `scripts/ebpf_policy_validate.sh` |
| **PERF-4** | No autonomous operational recovery (posture transitions manual) | Med → **Low** | **Kinetic state machine: FullPqc/EncryptedFallback/FailClosed (no Plaintext variant — unrepresentable), supervisor + handle_handshake_failure, OPERATION_MODE_FLAG = eBPF map value. MEASURED with real handshakes: failover 2.0 ms (fallback) / 3.7 ms (fail-closed), recovery 8.1 ms, per-event 2.2 ns; security fail-closed sticky; 9 tests + 400k-event fuzz** | `docs/KINETIC_STATE_MACHINE.md`; `src/kinetic.rs`; `tests/kinetic_failover_tests.rs` |
| **EBPF-P1** | eBPF policy was a single global `u32` posture flag, not a policy object | Med → **Low** | **Policy Object Model: structured 72-byte `syntriass_policy` {policy_id, posture, peer_identity_hash, cgroup_id, interface_id, fallback_allowed, expiry_ns, priority, audit_enabled} in a BPF HASH keyed by cgroup, distributed from userspace, enforced by the kernel. MEASURED on kernel 6.18.5: lookup+decision 343 ns (50k real connects), object push 4–9 µs, 72 B/policy; all four decision paths (allow / fail-closed / expired / no-policy=map-miss) each proven by a real connect (EPERM); no posture expresses plaintext** | `docs/POLICY_OBJECT_MODEL.md`; `ebpf/c/policy_v2.bpf.c`, `ebpf/c/policy_v2_loader.c`; `scripts/ebpf_policy_v2_validate.sh` |
| **EBPF-P2** | No policy composition: a single flag could not express node/app/flow layering | Med → **Low** | **Hierarchical Policy Engine: Global→Node→Application→Session resolution in the kernel, conflict resolution = Highest Priority Wins (ties break to the more specific level), expired/absent levels skipped, fail-closed when none apply. MEASURED on kernel 6.18.5: 4-level resolve+decision 895 ns (50k real connects), propagation 1–2 µs (live on next connect); 6/6 correctness scenarios — incl. priority-beats-specificity — each proven by a real connect with the winning level read back from the kernel** | `docs/HIERARCHICAL_POLICY.md`; `ebpf/c/policy_v2.bpf.c`, `ebpf/c/policy_v2_loader.c`; `scripts/ebpf_policy_hier_validate.sh` |
| **EBPF-P3** | Crypto requirements (full-PQC, no-fallback, hardware key) were not expressible or enforced as policy | Med → **Low** | **Cryptographic policy enforcement across both layers: FullPqcOnly/HybridOnly/FallbackAllowed/HardwareKeyRequired/NoClassicalFallback as a CryptoPolicy with a kernel-bit-compatible crypto_flags. Kernel gates fallback permission (5/5 real-connect scenarios; FullPqcOnly denies fallback at EPERM, ~895 ns resolve+gate); daemon enforces suite/hardware/classicality over a profile from a REAL handshake (10/10 rejection cases, 3.78 ns/decision), fail-closed on every Unknown attribute; kernel/userspace flags cross-checked** | `docs/CRYPTO_POLICY.md`; `src/crypto/crypto_policy.rs`, `ebpf/c/policy_v2.bpf.c`; `tests/crypto_policy_tests.rs`; `scripts/ebpf_crypto_policy_validate.sh` |
| **EBPF-P4** | No containment primitive to isolate a compromised confinement unit | Med → **Low** | **Quarantine Engine: a cgroup-keyed BPF map denies ALL egress (highest-priority deny, overriding every policy level) for three kinds — Temporary/AutoExpiry (auto-release at deadline) and Permanent (manual release only). MEASURED on kernel 6.18.5: propagation 2 µs (live next connect), enforcement 325 ns/connect (short-circuits resolve), manual release 15 µs; 4/4 real-connect recovery checks incl. Permanent not auto-recovering; reason=quarantine in the kernel audit stream** | `docs/QUARANTINE_ENGINE.md`; `ebpf/c/policy_v2.bpf.c`, `ebpf/c/policy_v2_loader.c`; `scripts/ebpf_quarantine_validate.sh` |
| **EBPF-P5** | No structured, categorized, measurable audit pipeline for kernel policy decisions | Med → **Low** | **Audit & telemetry pipeline over a 4 MiB RingBuf: categorized events (Decision/Violation/Fallback/Quarantine) with kernel emit timestamps + per-CPU emitted/dropped counters + tunable wakeup policy (closes the Phase-1 per-connect wakeup cost). MEASURED on kernel 6.18.5: ~36 µs avg / ~73 µs p99 end-to-end latency, ~22 000 eps sustained with 0 drops, and under a forced 4 s consumer stall 100 061 drops (35 %) counted exactly — accounting closes (recv≈emitted, no silent loss)** | `docs/AUDIT_TELEMETRY.md`; `ebpf/c/policy_v2.bpf.c`, `ebpf/c/policy_v2_loader.c`; `scripts/ebpf_audit_validate.sh` |
| **EBPF-P6** | No deployable, operator-selectable policy profiles spanning assurance↔resilience | Med → **Low** | **Three defence policy profiles enforced at both layers: Strategic Command (FullPqcOnly+HardwareKeyRequired, no fallback → fails closed), Tactical Comms (FullPqc+FallbackAllowed), Legacy Migration (HybridOnly+controlled fallback). Rust DefenceProfile (5/5 tests) with kernel-bit-compatible crypto_flags + kernel enforcement (6/6 real connects: Strategic degraded→EPERM, Tactical/Legacy degraded→encrypted link up). MEASURED on kernel 6.18.5: application 3–9 µs, switch 0.66 µs avg / 31 µs max over 3000 switches, live on next connect; no profile can express plaintext** | `docs/DEFENCE_POLICY_PROFILES.md`; `src/profiles.rs`, `ebpf/c/policy_v2.bpf.c`, `ebpf/c/policy_v2_loader.c`; `scripts/ebpf_profile_validate.sh` |
| **ARM-1** | ARM64 (aarch64) entirely unvalidated (build, correctness, performance) | High → **Medium** | **Functionally proven on the real ARM64 ISA: cross-build succeeds (artifacts verified aarch64); full suite 26/26, 193/193 tests pass under qemu-user emulation incl. a real aarch64 daemon child process; handshake wire bytes byte-identical to x86_64; all 3 benchmark suites executed (timings labeled [measured-emulated], no native estimates); BPF objects compile with __TARGET_ARCH_arm64; 1 real portability fix (stage-aware EINVAL in the kTLS probe). NATIVE performance + ARM64-kernel eBPF = BLOCKED here → committed native CI on ubuntu-24.04-arm + Graviton/Ampere plan** | `docs/ARM64_VALIDATION.md`, `docs/ARM64_BENCHMARKS.md`; `.cargo/config.toml`, `.github/workflows/arm64.yml`; `src/kernel_native.rs` |
| **MN-1** | Distributed / multi-node behaviour entirely unvalidated (identity distribution, fail-closed at scale) | High → **Medium** | **3/10/50-node full meshes validated: every one of 1 225 real OOB sessions establishes over real TCP with an encrypted both-ways echo; provisioning derives the same auth_secret on both sides; unprovisioned + wrong-capability identities rejected fleet-wide (fail closed). MEASURED: serialized establishment 0.13/1.98/53.9 s (rate ~23/s floor), whole-mesh VmHWM 6.4/7.2/11.2 MiB. Single-host loopback; multi-host RTT + networked policy/quarantine distribution transport + concurrent rate = BLOCKED here → multi-host plan committed** | `docs/MULTINODE_VALIDATION.md`, `docs/MULTINODE_BENCHMARKS.md`; `tests/multinode_tests.rs` |
| **DEP-1** | No end-to-end defence-deployment scenario (profiles + failure + quarantine + recovery together) | High → **Medium** | **5-node topology (Strategic Command→Regional Control→Tactical A/B→Legacy App) with all 3 profiles, REAL OOB sessions + real kinetic Supervisor + real CryptoPolicy + real wire-byte capture. 4 injected events MEASURED: node-failure degrade 891 µs / recover 174 ms (session re-established), Strategic fails CLOSED (never EncryptedFallback), policy re-task flip 80 ns, quarantine isolate 232 µs (0 served) / release 86 ms. Fail-closed preserved and ZERO cleartext (MARKER never on wire) before/during/after every event. In-process loopback; networked fleet convergence [design]** | `docs/DEFENCE_DEPLOYMENT_SCENARIO.md`, `docs/DEPLOYMENT_RECOVERY_RESULTS.md`; `tests/defence_deployment_tests.rs` |
| **MIG-1** | OOB identity lacked explicit revocation + a typed session capability for migration deployments | Low → **Low (extended)** | **Migration Platform Phase 1: identity revocation in the PeerRegistry (revoke/unrevoke/is_revoked; lookup fails closed on a revoked hash — proven by a real handshake rejected with Authentication after revocation) + a typed, epoch-rotating constant-time SessionToken over the provisioned secret. Re-measured: runtime handshake 2 464 B (−81.1 %), latency −81.6 %, 0 ML-DSA bytes on the wire; revocation 0 B when empty. Mutual auth + fail-closed preserved (9 oob tests). Runtime-wire SessionToken binding + CRL→registry feed = [design]** | `docs/OUT_OF_BAND_IDENTITY.md`; `src/crypto/oob.rs` |
| **MIG-3** | Migration-platform confirmation that posture enforcement lives in operational kernel state (Posture/Fallback/Session maps + userspace sync) | Low (confirm) | **Re-validated on kernel 6.18.5: Posture map (operation_mode) update 1–4 µs, Fallback map read, Session map (kernel→userspace) populated, userspace synchroniser drives live state; FullPqc→ALLOW, FailClosed→DENY (EPERM); no posture encodes plaintext. Production v2 engine (P1–P6) extends with structured objects/hierarchy/crypto/quarantine/audit/profiles [measured]** | `docs/EBPF_POLICY_ENGINE.md §5`; `ebpf/c/policy.bpf.c`, `ebpf/c/policy_v2.bpf.c`; `scripts/ebpf_policy_validate.sh` |
| **MIG-4** | No practical deployment path — required source-tree builds and manual setup | High → **Low–Medium** | **Deployment platform under `deploy/`: install.sh (+ --provision-self), validate-config (fail-closed ExecStartPre), hardened systemd unit, package.sh (offline tarball + SHA256SUMS), upgrade.sh (backup+revalidate+auto-restore on failure), rollback.sh, uninstall.sh. TESTED on this host: install→configure→validate(invalid⇒exit1, valid⇒exit0)→daemon binds from file config→package (2.8 MB, SHA256SUMS all-verified)→upgrade→rollback (binary byte-identical). systemd enable/start = [design] (no PID 1 here); package signing = [design]** | `docs/DEPLOYMENT_GUIDE.md`; `deploy/` |
| **MIG-5** | No air-gapped operation path (offline provisioning/updates/policy) | High → **Low–Medium** | **deploy/airgap.sh: offline identity provisioning (local seeds + export-identity/import-peer, checksum-verified), offline updates (package.sh tarball + SHA256SUMS + upgrade.sh), offline policy distribution (make-/apply-policy-bundle). TESTED on this host with ZERO network: two nodes cross-provisioned to VALID over 'removable media'; corrupted identity export AND tampered policy bundle both REFUSED (fail closed). Artifact SIGNING (authenticity vs active adversary) + offline CRL bundle = [design]** | `docs/AIR_GAPPED_OPERATIONS.md`; `deploy/airgap.sh`, `deploy/package.sh` |
| **MIG-6** | No fleet-management foundation for enterprise/theatre deployment | High → **Low–Medium** | **deploy/fleet.sh: offline-first node inventory (init/add/import-node from air-gap identity exports), per-profile policy distribution (offline checksummed bundles + assignments manifest), health reporting (ingest-health), and an identity/posture/health/liveness status roll-up that ALERTs on FailClosed nodes. TESTED at 120 nodes on this host (3 imported from real identity exports, 117 synthetic); no plaintext posture representable fleet-wide. Online push transport + signed inventory = [design]** | `docs/FLEET_MANAGEMENT.md`; `deploy/fleet.sh` |
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
