# iDEX Open Challenge — Validation Package

Aggregated validation evidence per workstream. Each entry: **Objective ·
Method · Results · Readiness Impact · Evidence References**. Tags: **[measured]
[tested] [implemented] [design]**. All results reproduce from the cited
scripts/tests; the master ledger is `docs/DEFENCE_READINESS_REVIEW.md`.

---

## 1. PQC Hardening

- **Objective.** Quantum-safe key exchange + identity, and a record layer that
  survives long sessions on lossy links without key-wear, replay, or downgrade.
- **Method.** Hybrid X25519+ML-KEM-768/1024 (FIPS 203) and Ed25519+ML-DSA-65
  (FIPS 204); HKDF-SHA256; AES-256-GCM records with explicit sequencing, an
  anti-replay window, and a rekey ratchet. Unit + property tests; a fuzzer
  exercised the record layer.
- **Results.** Round-trip key agreement and authenticated records pass; a
  fuzzer-found epoch-counter overflow (attacker-reachable) was **fixed** and
  regression-tested; zero false accepts on the anti-replay window. **[tested]**
- **Readiness Impact.** Establishes the post-quantum confidentiality foundation;
  ledger **PQC-2 → Mitigated**.
- **Evidence.** `docs/PQC_PROTOCOL_SPEC.md §4`; `src/crypto/session.rs`;
  `tests/session_hardening_tests.rs`.

## 2. Handshake DoS

- **Objective.** Prevent a flood from exhausting CPU via PQC work before peer
  validation.
- **Method.** A stateless-cookie admission gate on the live daemon path; per-source
  + global PQC-rate + concurrency caps; in-process, on-the-wire, and
  spawned-daemon tests including a distributed-source flood.
- **Results.** A **5 000-distinct-source** flood is held to the global burst —
  **25 PQC operations** — with legitimate handshakes still served. **[measured]**
- **Readiness Impact.** Availability under volumetric attack; ledger **C6 → Low**.
- **Evidence.** `docs/HANDSHAKE_DOS_HARDENING.md`; `src/handshake_guard.rs`;
  `tests/handshake_dos_tests.rs`, `tests/handshake_dos_integration.rs`.

## 3. Fail-Closed Assurance

- **Objective.** Prove no-cleartext / no-panic / concurrency-safe behaviour and
  audit the `unsafe` surface.
- **Method.** Property + leakage tests; **Miri** (undefined behaviour), **Loom**
  (exhaustive concurrency model checking), **cargo-fuzz** (libFuzzer + ASan);
  `#![deny(unused_must_use)]` crate-wide; unsafe-block audit.
- **Results.** **Two real bugs found and fixed** — a misaligned-reference UB in
  the config watcher and an attacker-reachable integer overflow in epoch handling;
  no plaintext operational state is representable (compiler-enforced); fuzz over
  400 000 events reached no forbidden state. **[tested]**
- **Readiness Impact.** Raises the assurance floor; ledger **FC-1 → Low**.
- **Evidence.** `docs/FAIL_CLOSED_ASSURANCE.md`; `tests/fail_closed_properties.rs`,
  `tests/loom_model.rs`; `fuzz/`; `scripts/run_miri.sh`.

## 4. Battlefield Resilience

- **Objective.** Characterise behaviour under degraded/contested network
  conditions with no plaintext leakage.
- **Method.** Packet-loss ladder (10/20/30/45 %), intermittent connectivity,
  daemon crash, memory exhaustion, CPU starvation, congestion — measuring
  delivery, goodput, latency, replay, reconnect, and cleartext leakage.
- **Results.** **Zero plaintext leaks** across the loss ladder; reconnect
  **~3.5 ms**; **249 handshakes/s** under congestion; crash and memory-exhaustion
  paths **fail closed**. Real `tc netem` qdisc layer is unavailable in this
  environment → host-side validation plan **[design]**. **[measured]**
- **Readiness Impact.** Tactical-edge credibility; ledger **C2 → Low–Medium**.
- **Evidence.** `docs/BATTLEFIELD_RESILIENCE.md`, `NETEM_RESULTS.md`,
  `RECOVERY_ANALYSIS.md`; `tests/battlefield_resilience.rs`.

## 5. Universal Interception

- **Objective.** Intercept egress for **all** host runtimes (not just those a
  userspace shim catches) and fail closed.
- **Method.** A kernel `cgroup/connect4` eBPF data plane (libbpf + clang),
  attached to a cgroup; coverage tested across 7 runtimes including the 4
  LD_PRELOAD blind spots (static, Go, musl, direct-syscall).
- **Results.** **7/7 runtimes intercepted**; non-compliant egress denied with
  **EPERM**; fail-closed on map miss. **[measured]**
- **Readiness Impact.** Kernel-level enforcement guarantee; ledger **C1 → Low**.
- **Evidence.** `docs/UNIVERSAL_INTERCEPTION.md`; `ebpf/c/`;
  `scripts/ebpf_coverage_validate.sh`.

## 6. ARM64 Validation

- **Objective.** Prove the platform builds and behaves correctly on ARM64.
- **Method.** Cross-compile to `aarch64-unknown-linux-gnu`; run the **entire**
  test suite on the ARM64 ISA under `qemu-aarch64-static` + binfmt (the daemon
  spawns as a real aarch64 ELF); compile the eBPF objects with
  `-D__TARGET_ARCH_arm64`; committed native CI workflow.
- **Results.** **26/26 suites, 193 tests pass** on the ARM64 ISA; wire artifacts
  **byte-identical** to x86_64; one portability bug fixed (stage-aware EINVAL in
  the kTLS probe). Native silicon performance + ARM64-kernel eBPF load are
  **[design]**. **[measured-emulated]**
- **Readiness Impact.** Portability to the dominant defence-edge architecture;
  ledger **ARM-1 → Medium**.
- **Evidence.** `docs/ARM64_VALIDATION.md`, `ARM64_BENCHMARKS.md`;
  `.github/workflows/arm64.yml`.

## 7. Multi-Node Validation

- **Objective.** Validate distributed behaviour — identity distribution, session
  establishment, fleet-wide fail-closed.
- **Method.** 3/10/50-node full meshes of independent nodes (own identity,
  registry, real TCP listener) on loopback; every edge a **real** OOB session with
  an encrypted both-ways echo; one-time PQ provisioning per pair.
- **Results.** **1 225 real OOB sessions** (at 50 nodes) all establish; an
  unprovisioned identity and a wrong-capability peer are **both rejected
  fleet-wide**; whole-mesh memory 11.2 MiB at 50 nodes. Multi-host RTT + networked
  distribution transport are **[design]**. **[measured]**
- **Readiness Impact.** Distributed correctness + fail-closed at scale; ledger
  **MN-1 → Medium**.
- **Evidence.** `docs/MULTINODE_VALIDATION.md`, `MULTINODE_BENCHMARKS.md`;
  `tests/multinode_tests.rs`.

## 8. Deployment Validation

- **Objective.** Make the platform installable, air-gap operable, and
  fleet-manageable without source changes.
- **Method.** `deploy/` toolchain — `install.sh`, `package.sh` (offline tarball +
  SHA256SUMS), `validate-config.sh` (fail-closed `ExecStartPre`), systemd unit,
  `upgrade.sh`/`rollback.sh`, `airgap.sh` (checksum-gated offline identity/policy),
  `fleet.sh` (100+-node inventory/health/distribution). Executed on this host.
- **Results.** Fresh host **install → configure → validate → run** from the
  offline package with no source edits; tampered identity export **and** policy
  bundle **refused** (fail closed); **120-node** fleet status + offline policy
  distribution. systemd start path + online fleet transport are **[design]**.
  **[tested]**
- **Readiness Impact.** Field-deployability; ledger **MIG-4/5/6 → Low–Medium**.
- **Evidence.** `docs/DEPLOYMENT_GUIDE.md`, `AIR_GAPPED_OPERATIONS.md`,
  `FLEET_MANAGEMENT.md`; `deploy/`.

## 9. Key Storage Validation

- **Objective.** Protect identity keys with a backend-agnostic layer spanning
  software and hardware roots of trust.
- **Method.** `KeyProtector` trait with software (AES-256-GCM, HKDF passphrase
  KEK), TPM2 (swtpm), and PKCS#11 (SoftHSM2) backends, exercised end-to-end
  through the real Rust adapter, including a sealed-to-hardware negative test.
- **Results.** Software protector fully tested; TPM2 and PKCS#11 backends
  validated end-to-end (a different TPM cannot unseal); raw seeds never on disk.
  Physical-device acceptance is **[design]**. **[tested]**
- **Readiness Impact.** Sovereign key custody; ledger **KS-1 → Low–Medium**.
- **Evidence.** `docs/KEY_STORAGE_ARCHITECTURE.md`, `TPM_INTEGRATION.md`,
  `HSM_INTEGRATION.md`; `src/keystore.rs`; `tests/keystore_external_tests.rs`.

---

## Reproduce everything

```sh
cargo fmt --check && cargo clippy --all-targets -- -D warnings
cargo build --release --locked && cargo test --release --locked        # 28 suites
cargo bench --bench oob_benchmarks                                       # size/latency deltas
sudo bash scripts/ebpf_policy_v2_validate.sh                             # kernel enforcement (root)
sudo bash scripts/ebpf_quarantine_validate.sh
sudo bash scripts/ebpf_profile_validate.sh
bash deploy/fleet.sh init /tmp/inv.tsv                                   # fleet foundation
```

Every number in this package is the output of one of the above (or the documents
they reference). Nothing is hand-entered or projected; the `[design]` items are
the ones that require hardware/infra absent from this environment.
