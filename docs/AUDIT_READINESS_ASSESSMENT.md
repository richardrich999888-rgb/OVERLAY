# SYNTRIASS Overlay — Audit Readiness Assessment

> **Internal Security Review / Pre-Audit Assessment.** This evaluates readiness to
> **enter** an external independent security audit / cryptographic review. It is
> not itself such an audit, and confers no certification or compliance.

## Audit Readiness Score: **5.5 / 10**

The codebase is **structurally auditable** — small, well-organised, memory-safe
Rust + a compact verifier-checked eBPF program, with unusually disciplined
evidence and reproducible tests. That *raises* readiness. But three open Critical
findings and several architectural gaps mean an external assessor would surface
material issues today; entering an audit now would likely produce a "remediate and
re-submit" outcome rather than a pass. Closing the Criticals first converts a
likely-fail into a credible audit entry.

## What helps an external audit (strengths)

| Strength | Evidence |
|---|---|
| Memory-safe core in Rust; small TCB | ~10.8k lines Rust + ~2.2k lines eBPF C |
| Reproducible test harness | 28 test suites, `cargo bench`, `scripts/ebpf_*_validate.sh` |
| Existing assurance tooling | Miri, Loom, cargo-fuzz, property/leakage tests |
| Standards-aligned crypto | NIST FIPS 203 (ML-KEM) / 204 (ML-DSA), HKDF-SHA256, AES-256-GCM |
| Honest, tagged documentation | `[measured]/[tested]/[implemented]/[design]` discipline |
| Clear fail-closed *posture* model | no representable plaintext operational mode |
| This pre-audit itself | findings are catalogued, classified, and partially remediated |

## What blocks a clean audit (gaps to close first)

1. **Open Critical findings** CR-2 (fork nonce reuse), CR-3 (air-gap MITM),
   CR-4 (supply-chain RCE) — any one is a likely audit-fail.
2. **Kernel egress coverage** (HI-1) and **fail-open-on-detach** (HI-2) — an eBPF
   reviewer will find these immediately.
3. **Interceptor robustness** (HI-3/HI-4/HI-5) — fd lifecycle / TOCTOU / role
   confusion in the most safety-critical module.
4. **Documentation-vs-code drift** — three over-broad claims (kernel no-plaintext,
   air-gap tamper-proof, plaintext-unrepresentable) must be qualified, or the
   assessor will treat the docs as unreliable (a trust multiplier against you).

## Audit-entry checklist

- [ ] Close CR-2, CR-3, CR-4 with their validation gates.
- [ ] Close HI-1, HI-2 (kernel coverage + link pinning).
- [ ] Close the Low-effort deploy hardening HI-6…HI-9.
- [ ] Correct the three over-broad documentation claims (§8 of the pre-audit
      review).
- [ ] Add the fault-injection test for CR-1 (forced `getsockopt`=EINTR).
- [ ] Add a fork-reuse integration test (proves CR-2 closed).
- [ ] Add IPv6/UDP egress-denied kernel tests (proves HI-1 closed).
- [ ] Produce a threat model + trust-boundary document for the assessor (the
      kernel/userspace decoupling in E-3 should be explicit).
- [ ] Provide a reproducible build with a pinned toolchain + `cargo audit` /
      dependency SBOM for the supply-chain reviewer.

## Scope an external audit should cover (recommended SOW)

1. **Cryptographic protocol review** — OOB handshake (replay/KCI/key-confirmation),
   transcript binding, rekey ratchet, fallback PSK path, revocation/agility.
2. **Implementation review** — RustCrypto usage, constant-time paths, the 87
   `unsafe` blocks, the FFI panic-shield profile dependency.
3. **eBPF/kernel review** — complete egress coverage, fail-open-on-detach, map
   isolation, privilege boundaries.
4. **Supply-chain / air-gap review** — signing design (CR-3/CR-4), reproducible
   builds, SBOM.
5. **Side-channel evaluation** on representative hardware.
6. **Red-team engagement** against a deployed instance (fork-reuse, fd-reuse,
   protocol-bypass, downgrade, MITM-via-provisioning).

## Items explicitly requiring INDEPENDENT review (cannot be self-attested)

- Formal/semi-formal cryptographic analysis of the OOB protocol.
- Kernel egress-completeness and fail-open behaviour on a live kernel.
- Air-gap / supply-chain signing design.
- Side-channel resistance on hardware.

## Bottom line

The platform is a **credible audit candidate** with a disciplined evidence base,
but it is **not yet audit-ready**: close the three open Criticals and the two
kernel-coverage Highs, qualify the over-broad docs, and re-score (target
**≥ 7.5/10**) before commissioning an external assessment. Entering an audit now
would most likely return "remediate and re-submit" — avoidable by doing the
gating fixes first.

## Disclaimers (mandatory)

- This is an **Internal Security Review / Pre-Audit Assessment**, not an
  independent certification.
- No compliance with any standard (Common Criteria, FIPS 140-3 validation, etc.)
  is claimed or implied.
- No audit is claimed to be complete. Findings are reviewer opinion from source
  reading and have not been validated by exploitation in production.
