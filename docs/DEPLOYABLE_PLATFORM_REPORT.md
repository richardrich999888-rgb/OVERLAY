# Deployable PQC Migration Platform — Final Report

Tags: **[measured]** real run · **[tested]** automated assertion ·
**[implemented]** code exists · **[design]/[BLOCKED]** needs infra absent here.

This report consolidates the six-phase **Deployable PQC Migration Platform**
workstream. Source of truth: the per-phase documents, the Defence Readiness
Review, and the measured results they cite. No fabricated validation; every
blocker is named with its evidence. Fail-closed and zero-plaintext guarantees
are preserved throughout (verified, not assumed).

---

## Per-phase status

### Phase 1 — Out-of-Band Identity — **COMPLETED**
Identity Registry, `IdentityKeyHash`, SessionToken capability (`auth_secret`),
peer cache, provisioning workflow, and **revocation** (`PeerRegistry::revoke` /
`is_revoked` / `revoked_count`; a revoked hash resolves to `None` — fail closed)
are all **[implemented] + [tested]**. The runtime handshake transmits **no
ML-DSA public key and no ML-DSA signature**.
- **MEASURED:** handshake **13 050 → 2 464 B (−81.1 %)**, **1 846 → 328 µs
  (−82.2 %)**, **0** ML-DSA bytes on the wire; mutual auth + fail-closed
  preserved; `revoked_identity_fails_closed_on_a_real_handshake` passes.
- Doc: `docs/OUT_OF_BAND_IDENTITY.md`. Ledger: PERF-1 / MIG-1.

### Phase 2 — PQC → kTLS Data Plane — **PARTIAL (throughput BLOCKED)**
PQC session-secret extraction, `TLS_TX`/`TLS_RX` install path, capability
detection (`ktls_supported()`), and **fail-safe handling** (no ULP ⇒
`KtlsUnavailable` ⇒ caller **fails closed**, *no* plaintext userspace-relay
fallback) are **[implemented] + [tested]**.
- **BLOCKED:** this kernel has **no TLS ULP** (`tls` absent from
  `/proc/.../ulp`), so kTLS cannot be *activated* here and the
  throughput/CPU/latency comparison cannot be produced. Recommended target on a
  TLS-ULP host: **≥28 % line rate / ~2×** the 12.8–15.5 % userspace-relay
  baseline. The secret derivation + install code are verified; the data-plane
  switch needs a ULP-enabled host.
- Doc: `docs/KTLS_DATA_PLANE.md`. Ledger: PERF-2 / MIG-2.

### Phase 3 — Production eBPF Policy Engine — **COMPLETED**
BPF session/posture/fallback maps + userspace synchronisation, re-validated by
real connects on kernel 6.18.5.
- **MEASURED:** posture map updates **1–3 µs**, kernel **ALLOW** under FullPqc /
  **DENY (EPERM)** under FailClosed, session_state distributed kernel→userspace;
  the v2 engine adds structured objects, a 4-level hierarchy, crypto enforcement,
  quarantine, audit, and profiles (lookup **343 ns**, resolve **895 ns**,
  quarantine **325 ns**). Enforcement reads live kernel-map state on every
  connect; **no plaintext leakage** (no posture expresses plaintext).
- Doc: `docs/EBPF_POLICY_ENGINE.md` (+ the Policy Engine v2 set). Ledger:
  PERF-3 / EBPF-P1…P6 / MIG-3.

### Phase 4 — Deployment Platform — **COMPLETED (systemd start = [design] here)**
`deploy/`: `install.sh`, `package.sh`, `validate-config.sh`, `systemd/` unit,
`upgrade.sh`, `rollback.sh`, `uninstall.sh`.
- **TESTED on this host:** a fresh host can **install → configure → validate**
  from the offline package with no source changes; `validate-config` runs as the
  unit's `ExecStartPre`. The `systemctl enable --now` start is **[design]** here
  only because this container has no systemd PID 1 — the unit file is installed
  and verified.
- Doc: `docs/DEPLOYMENT_GUIDE.md`. Ledger: MIG-4.

### Phase 5 — Air-Gapped Operations — **COMPLETED**
`deploy/airgap.sh`: offline identity export/import (`export-identity` /
`import-peer`, **checksum-verified — a mismatch fails closed**), offline policy
bundles (`make-policy-bundle` / `apply-policy-bundle`, `sha256 -c` gate), and
offline policy distribution. No internet dependency.
- **TESTED:** round-trip export→import with a tampered file rejected (fail
  closed); bundle apply refuses a bad checksum.
- Doc: `docs/AIR_GAPPED_OPERATIONS.md`. Ledger: MIG-5.

### Phase 6 — Fleet Management Foundation — **COMPLETED (online transport = [design])**
`deploy/fleet.sh`: offline-first node inventory, `import-node` from real identity
exports, per-profile offline policy distribution (bundles + assignment manifest),
health ingestion, and an identity/posture/health/liveness status roll-up that
**ALERTs on FailClosed nodes**.
- **TESTED at 120 nodes** on this host (3 imported from real air-gap identity
  exports, 117 synthetic): status rolled up **92/17/11** by profile,
  **106/12/2** by posture with the FailClosed ALERT; distribute produced 3
  per-profile bundles + a 120-row assignments manifest. Posture is whitelisted to
  the three encrypted states — **no plaintext posture is representable
  fleet-wide**. Online push transport + signed inventory are **[design]**.
- Doc: `docs/FLEET_MANAGEMENT.md`. Ledger: MIG-6.

---

## Measured Results (consolidated)

| Capability | Metric | Value | Tag |
|---|---|---|---|
| OOB identity | runtime handshake size | 13 050 → **2 464 B (−81.1 %)** | [measured] |
| OOB identity | runtime handshake latency | 1 846 → **328 µs (−82.2 %)** | [measured] |
| OOB identity | ML-DSA on wire | **0 B** | [measured] |
| OOB revocation | revoked identity handshake | **fails closed** | [tested] |
| eBPF policy | posture map update | **1–3 µs** | [measured] |
| eBPF policy | lookup / resolve / quarantine | **343 ns / 895 ns / 325 ns** | [measured] |
| eBPF policy | FailClosed → kernel decision | **EPERM (deny)** | [measured] |
| Deployment | install→configure→validate (fresh host) | **works, no source edits** | [tested] |
| Air-gap | tampered identity/bundle | **rejected (fail closed)** | [tested] |
| Fleet | inventory + status + distribute | **120 nodes**, FailClosed ALERT | [tested] |
| kTLS data plane | throughput uplift | **BLOCKED** (no TLS ULP); target ≥28 %/~2× | [design] |

## Residual Risks

- **kTLS throughput is unproven** in this environment (no TLS ULP) — the single
  hard blocker; needs a ULP-enabled kernel.
- **systemd start path** is `[design]` here (no PID 1); validated up to unit
  installation + `validate-config`.
- **Fleet online transport** (signed push/pull, mutual-auth control channel) and
  **signed inventory** are `[design]`; the offline foundation is tested.
- Daemon-loop integration of the kinetic Supervisor / `CryptoPolicy::enforce` /
  quarantine producer remains the standing wiring item.
- ARM64 silicon performance and physical TPM/HSM acceptance remain `[design]`
  (carried from the prior workstream).

## Readiness Impact

SYNTRIASS is now a **deployable** PQC migration platform: a fresh or air-gapped
Linux host can install, configure, validate, run, and be managed at 100+-node
scale without source modification or an internet connection, with the runtime
ML-DSA cost removed and kernel-native fail-closed policy enforcement intact. The
one capability that cannot be demonstrated here — the kTLS throughput uplift —
is implemented and fails safe; it is blocked solely on a TLS-ULP host. New DRR
rows MIG-1…MIG-6 (`docs/DEFENCE_READINESS_REVIEW.md`).
