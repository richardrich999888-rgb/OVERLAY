# iDEX Open Challenge — Defence Relevance Report

How SYNTRIASS Overlay applies to each Indian defence consumer. Capability claims
are tagged to repository evidence (**[measured] [tested] [implemented]
[design]**); force-specific deployment and benefit statements are operational
analysis built on those capabilities, not additional product claims.

---

## Indian Army

**Current Challenge.** Tactical communications over low-bandwidth, jammed, and
intermittently-partitioned RF/SATCOM links across a dispersed force; field hosts
are at risk of capture; the deployed application estate cannot be rewritten for
PQC on operational timelines.

**Deployment Model.** **Tactical Communications profile** at battalion/brigade
nodes; **Legacy Migration profile** to wrap existing field applications
unchanged; **Strategic Command profile** at corps/command HQ. Air-gapped forward
enclaves provisioned via removable-media identity export/import. Fleet managed
offline from a regional control node.

**Expected Benefit.** Quantum-safe links with an **81 %-smaller handshake**
[measured] (critical on constrained tactical bearers); autonomous
FullPqc→EncryptedFallback→FailClosed recovery keeps an **encrypted** link up under
jamming, **never plaintext** [measured]; a captured host **cannot leak in clear**
(kernel fail-closed, 343 ns enforcement) [measured].

**Operational Value.** Maintains confidential C2 and situational-awareness data
flow at the tactical edge under EW pressure, while migrating the existing estate
without re-fielding software.

---

## Indian Navy

**Current Challenge.** Long-endurance platforms (ships, submarines) with
high-value, long-secrecy-lifetime traffic over SATCOM and shore data links;
intermittent connectivity; strict compartmentation between networks.

**Deployment Model.** **Strategic Command / Tactical profiles** across
ship-board enclaves; **Legacy Migration** for combat-management and sensor
applications; air-gapped provisioning for compartmented networks; per-platform
fleet inventory rolled up at shore HQ when connectivity allows (offline-capable).

**Expected Benefit.** HNDL protection for decades-secrecy maritime traffic
(hybrid X25519+ML-KEM removes classical-only key exchange from the wire)
[implemented]+[tested]; deterministic fail-closed under SATCOM dropout; sealed
keys to a hardware root of trust (TPM2/PKCS#11 adapter [tested]; physical
[design]).

**Operational Value.** Confidentiality of strategic maritime and sensor data is
preserved against a future quantum adversary recording today, with availability
maintained across the connectivity gaps inherent to naval operations.

---

## Indian Air Force

**Current Challenge.** Sensor-to-shooter and ISR data links, and base/command
C4I, carrying time-critical and long-value data; heterogeneous host runtimes;
endpoints in forward locations.

**Deployment Model.** **Tactical profile** on data-link gateways; **Strategic
profile** at command centres; kernel `cgroup/connect4` enforcement attached
per-workload (per-pod in containerised C4I). Fleet posture monitored centrally
with FailClosed alerting.

**Expected Benefit.** Universal interception in the **kernel** covers all host
runtimes — including static binaries, Go, musl, and direct-syscall paths that
userspace shims miss (7/7 runtimes intercepted) [measured]; structured policy and
quarantine isolate a suspect node in **325 ns** [measured]; audit pipeline gives
accredited observability (~22 000 events/s, exact drop accounting) [measured].

**Operational Value.** Protects high-tempo ISR/data-link confidentiality and
gives commanders a kernel-level guarantee plus auditable evidence that no
protected node is communicating in clear.

---

## Strategic Forces

**Current Challenge.** The highest-secrecy, longest-lifetime traffic in the
inventory — exactly the HNDL worst case — across strictly air-gapped command and
control enclaves where no internet dependency is tolerable.

**Deployment Model.** **Strategic Command profile** exclusively
(FullPqcOnly + HardwareKeyRequired, **no fallback — fails closed**); fully
air-gapped provisioning and policy distribution via checksum-verified removable
media; hardware-sealed identity keys.

**Expected Benefit.** Maximum-assurance posture: a degradation **fails closed**
rather than ever weakening the channel (proven: Strategic Command never enters
EncryptedFallback) [measured]; **no plaintext state is representable** anywhere
[tested]; tampered offline artifacts are refused [tested].

**Operational Value.** Provides the strongest available guarantee that strategic
C2 traffic is both quantum-safe and incapable of silent downgrade, deployable
into air-gapped enclaves with sovereign cryptographic control.

---

## Defence Networks (DCN / tri-service backbone, C4I)

**Current Challenge.** A large, heterogeneous, multi-tier backbone connecting
strategic, regional, and tactical tiers; mixed legacy and modern applications;
the need to migrate to PQC estate-wide without a flag-day rewrite.

**Deployment Model.** Tiered profiles — Strategic at the core, Tactical at the
regional/edge tiers, Legacy Migration for the long tail of existing applications
— composed via the **hierarchical policy engine** (Global→Node→Application→
Session, highest-priority-wins) [measured]. Validated end-to-end on a
representative 5-node Strategic→Regional→Tactical→Legacy topology with node
failure, re-tasking, quarantine, and recovery — **zero cleartext throughout**
[measured].

**Expected Benefit.** Incremental, policy-driven PQC migration of the whole
estate; central posture/health visibility at 100+-node scale (tested to 120
nodes) [tested]; consistent fail-closed enforcement from core to edge.

**Operational Value.** A single sovereign overlay migrates the defence backbone
to quantum-safe transport on a software timeline, with kernel-enforced assurance
and fleet-wide observability — without replacing the applications that run on it.

---

## Cross-cutting fit

- **Sovereign:** NIST-standard PQC implemented in memory-safe Rust on Linux; no
  foreign cryptographic dependency.
- **Migration-first:** no application source changes — the overlay wraps the
  existing estate.
- **Air-gap native:** offline provisioning, updates, and policy with fail-closed
  integrity checks [tested].
- **Evidence-disciplined:** every capability above is reproducible from the
  repository; the gaps (kTLS throughput, native ARM64, physical HSM, multi-host)
  are explicitly `[design]`, not hidden.
