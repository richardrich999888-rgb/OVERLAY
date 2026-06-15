# iDEX Open Challenge — Technology Readiness Package

*Assessment uses repository evidence only. Tags: **[measured] [tested]
[implemented] [design]**. No inflated claims — every TRL judgement is bounded by
what is reproducible in-repo, and every gap is named.*

## Current TRL: **5**

**TRL 5 — component/subsystem validation in a relevant environment.** SYNTRIASS's
components are integrated and validated together on commodity Linux with **real
kernel enforcement**, under **simulated contested conditions** (packet loss, DoS
flood, node failure, quarantine, multi-node mesh, ARM64 ISA). It is **not yet**
TRL 6, because the system has not been demonstrated on representative **hardware**
and **real multi-host networks** end-to-end; those steps are scoped below and
are honestly marked `[design]`.

### Why not lower (≥ TRL 5)

- Components are not isolated breadboards — they are **integrated** and exercised
  together (handshake + eBPF enforcement + kinetic recovery + profiles) in
  end-to-end scenarios [measured].
- Validation is in a **relevant environment**: real Linux kernel (6.18.5) BPF
  enforcement, real TCP, real PQC handshakes, simulated contest.

### Why not higher (< TRL 6)

- The kTLS data-plane throughput uplift is **BLOCKED/[design]** (no kernel TLS
  module in the test environment).
- ARM64 results are **[measured-emulated]** (QEMU), not native silicon.
- Multi-node is **single-host loopback**; real multi-host network behaviour is
  `[design]`.
- TPM/HSM validated against **software substitutes**; physical-device acceptance
  is `[design]`.

## Evidence Supporting TRL 5

| Capability | Evidence | Tag |
|---|---|---|
| Hybrid PQC handshake + hardened record layer | `docs/PQC_PROTOCOL_SPEC.md`; `cargo test` | [tested] |
| OOB identity (−81 % size / −82 % latency, 0 ML-DSA on wire) | `docs/OUT_OF_BAND_IDENTITY.md`; `benches/oob_benchmarks.rs` | [measured] |
| Kernel `cgroup/connect4` enforcement, 7/7 runtimes, EPERM | `docs/UNIVERSAL_INTERCEPTION.md`; `scripts/ebpf_coverage_validate.sh` | [measured] |
| eBPF Policy Engine v2 (343 ns lookup, 895 ns resolve, 325 ns quarantine, ~22k eps audit) | `docs/POLICY_OBJECT_MODEL.md`…`DEFENCE_POLICY_PROFILES.md`; `scripts/ebpf_*_validate.sh` | [measured] |
| Anti-DoS (5 000-source flood → 25 PQC ops) | `docs/HANDSHAKE_DOS_HARDENING.md` | [measured] |
| Fail-closed assurance (Miri/Loom/fuzz, 2 bugs fixed, no plaintext state) | `docs/FAIL_CLOSED_ASSURANCE.md` | [tested] |
| Kinetic recovery (failover 2.0 ms, recovery 8.1 ms) | `docs/KINETIC_STATE_MACHINE.md` | [measured] |
| Battlefield resilience (10–45 % loss, 0 plaintext leaks) | `docs/BATTLEFIELD_RESILIENCE.md` | [measured] |
| Multi-node (50 nodes / 1 225 sessions, fleet-wide fail-closed) | `docs/MULTINODE_VALIDATION.md` | [measured] |
| Defence deployment scenario (5-node, 4 events, zero cleartext) | `docs/DEFENCE_DEPLOYMENT_SCENARIO.md` | [measured] |
| ARM64 ISA (193 tests pass) | `docs/ARM64_VALIDATION.md` | [measured-emulated] |
| Key storage (software + TPM2/PKCS#11 adapter) | `docs/KEY_STORAGE_ARCHITECTURE.md` | [tested] |
| Deployment / air-gap / fleet (120-node fleet) | `docs/DEPLOYMENT_GUIDE.md`, `AIR_GAPPED_OPERATIONS.md`, `FLEET_MANAGEMENT.md` | [tested] |

## Open Risks

| Risk | Status | Mitigation owner |
|---|---|---|
| kTLS throughput unproven (no TLS ULP here) | [design]/BLOCKED | Path-to-TRL-6 #1 |
| ARM64 silicon performance unknown (emulated only) | [design] | Path-to-TRL-6 #2 |
| Multi-host network behaviour unmeasured | [design] | Path-to-TRL-6 #3 |
| Physical TPM/HSM acceptance | [design] | Path-to-TRL-6 #4 |
| No external cryptographic review yet | open | Path-to-TRL-6 #5 |
| Daemon-loop integration of Supervisor/CryptoPolicy/quarantine | [design] | Path-to-TRL-6 #6 |

## Path to TRL 6 (system demonstration in a relevant environment)

1. **kTLS activation on a TLS-ULP kernel** — install `TLS_TX`/`TLS_RX`, measure
   throughput/CPU/latency vs the userspace-relay baseline (target ≥28 % line /
   ~2×). Converts MIG-2 from `[design]` to `[measured]`.
2. **Native ARM64 hardware** — run the committed `arm64.yml` workflow on a real
   `ubuntu-24.04-arm` / Graviton / Ampere host; record native latency/throughput
   and load the eBPF engine on an ARM64 kernel.
3. **Real multi-host pilot (3 → 10 nodes)** — replace loopback with real IPs;
   measure cross-host session establishment, policy/quarantine convergence with
   real RTT; add a signed online policy-distribution transport.
4. **Physical TPM/HSM acceptance** on representative hardware.
5. **Independent cryptographic review** of the protocol + implementation, with
   findings closed.
6. **Daemon-loop integration** — wire the kinetic Supervisor, `CryptoPolicy::
   enforce`, and the quarantine producer into the live connection loop.

**Exit criterion for TRL 6:** an integrated SYNTRIASS deployment demonstrated on
representative hardware across a real multi-host network, with the kTLS data
plane active, in a defence-relevant operational scenario — every `[design]` tag
above replaced by `[measured]`/`[tested]`.

## Path to TRL 7 (prototype demonstration in an operational environment)

1. **Defence pilot** at a consenting unit/establishment: deploy across a
   representative slice of a real network tier (Strategic/Tactical/Legacy),
   wrapping live (non-critical first) applications.
2. **Accreditation evidence** assembled for the relevant authority (crypto
   approval, security testing, configuration baselines).
3. **Operational soak** — sustained multi-week run with fleet management,
   upgrades/rollbacks, and incident handling under real operational load.
4. **Scale validation** to the pilot's full node count (target 50–100+ nodes)
   with measured convergence and availability.
5. **Field hardening** — packaging, operator tooling, and support processes
   matured against pilot feedback.

**Exit criterion for TRL 7:** SYNTRIASS prototype operating in a real defence
operational environment over a representative period, with measured availability,
security, and manageability, and accreditation in progress.

## Honest bottom line

SYNTRIASS is a **credible TRL 5** with an unusually disciplined evidence trail:
the claims that are made are reproducible, and the claims that cannot yet be made
are labelled `[design]` rather than asserted. The path to TRL 6/7 is concrete,
funded by a SPARK grant + pilot, and gated on converting six named `[design]`
items to measured results — not on inventing new science.
