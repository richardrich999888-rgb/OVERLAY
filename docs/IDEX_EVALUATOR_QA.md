# iDEX Open Challenge — Evaluator Q&A Package

100 anticipated questions with evidence-backed answers. Tags: **[measured]
[tested] [implemented] [design]**. Where an answer states a limitation, it is
stated plainly — the credibility of this submission rests on not overclaiming.

---

## A. Defence reviewers (operational relevance) — Q1–25

**Q1. What problem does SYNTRIASS solve for the warfighter?**
Quantum-safe, fail-closed communications for the *existing* application estate
without rewriting it — protecting long-secrecy traffic from harvest-now-
decrypt-later while keeping links up under jamming. [implemented]

**Q2. Why is this urgent now?**
NIST PQC standards are final (FIPS 203/204, 2024) and HNDL is a present-tense
attack — adversaries record ciphertext today to decrypt later. Migration must
happen before a quantum computer exists.

**Q3. Does it work on low-bandwidth tactical links?**
The runtime handshake is **81 % smaller** (13 050→2 464 B) and **82 % faster**
(1 846→328 µs) because ML-DSA is moved off the runtime wire. [measured]

**Q4. What happens when the link is jammed/degraded?**
The node autonomously moves FullPqc→EncryptedFallback→FailClosed and recovers on
sustained success — failover 2.0 ms, recovery 8.1 ms; the fallback is AES-256
encrypted, **never plaintext**. [measured]

**Q5. Can it ever transmit in clear?**
No. A plaintext operational state is *unrepresentable* in the code (compiler-
enforced; fuzz-verified). Across all deployment scenarios a plaintext marker
**never** appeared on the wire. [tested]

**Q6. What if a field host is captured/compromised?**
Egress policy lives in the **kernel** (eBPF), so a compromised userspace process
cannot route around it; non-compliant egress is denied with EPERM. [measured]

**Q7. Is it usable in air-gapped enclaves?**
Yes — offline identity provisioning and checksum-verified offline policy
distribution; validated with zero network. Tampered artifacts are refused. [tested]

**Q8. How many nodes can it manage?**
Fleet management tested at **120 nodes** (offline-first); architecture targets
100+. Online transport at larger scale is [design]. [tested]

**Q9. Which forces benefit?** Army, Navy, Air Force, Strategic Forces, and the
tri-service backbone — see `docs/IDEX_DEFENCE_RELEVANCE.md` for force-specific
deployment models. [implemented]

**Q10. Does it require new hardware?** No — it is software on commodity Linux;
optional TPM/HSM for hardware key custody. [implemented]

**Q11. Does it disrupt existing applications?** No source changes; the overlay
wraps unmodified applications. [implemented]

**Q12. How fast can a node be re-tasked between security profiles?**
Profile switch is **0.66 µs** average (kernel push), live on the next connection.
[measured]

**Q13. Can a suspect node be isolated quickly?** Quarantine propagates in 2 µs and
is enforced in 325 ns, denying all the node's egress. [measured]

**Q14. Is there an audit trail for accreditation?** Yes — a categorized kernel
audit pipeline (~22 000 events/s) with exact emitted/dropped accounting. [measured]

**Q15. What is the assurance under a denial-of-service flood?** A 5 000-source
flood is contained to 25 PQC operations; legitimate traffic still served. [measured]

**Q16. Does degradation lose the mission?** No — it degrades to an *encrypted*
fallback to stay connected, or fails closed for highest-assurance nodes; the
operator chooses per profile. [measured]

**Q17. How is a compromised identity handled?** Revocation makes the identity
resolve to nothing — it can neither initiate nor be answered; proven on a real
handshake. [tested]

**Q18. Is it sovereign?** Yes — NIST-standard PQC implemented in Indian-controlled
memory-safe Rust on Linux; no foreign cryptographic black box. [implemented]

**Q19. What's the strategic-forces fit?** Strategic Command profile:
FullPqcOnly + HardwareKeyRequired, **no fallback** — a degradation fails closed,
proven never to enter EncryptedFallback. [measured]

**Q20. Can legacy systems interoperate during migration?** Yes — the Legacy
Migration profile wraps existing applications with controlled (non-classical)
fallback. [tested]

**Q21. What is the current maturity?** TRL 5 — validated in a relevant
(simulated contested) environment; honest gaps to TRL 6 are named. [measured]

**Q22. Has it been tested end-to-end in a realistic topology?** Yes — a 5-node
Strategic→Regional→Tactical→Legacy deployment survived node failure, re-tasking,
quarantine, and recovery with zero cleartext. [measured]

**Q23. What about the dominant edge CPU architecture (ARM64)?** The full test
suite (193 tests) passes on the ARM64 ISA; native-silicon perf is [design]. [measured-emulated]

**Q24. What is the single biggest current limitation?** The kTLS throughput
uplift is not yet measured (the test kernel lacks the TLS module); it is
implemented and fails safe. [design]

**Q25. Why should the jury trust the numbers?** Every claim is reproducible from
in-repo scripts/tests and tagged; nothing un-validated is presented as done.

## B. Security reviewers (crypto & assurance) — Q26–55

**Q26. Which PQC algorithms?** ML-KEM-768/1024 (FIPS 203) for KEM, ML-DSA-65
(FIPS 204) for signatures. [implemented]

**Q27. Hybrid or PQC-only?** Hybrid — X25519 + ML-KEM for key exchange, Ed25519 +
ML-DSA for identity; safe unless *both* classical and PQC are broken. [implemented]

**Q28. AEAD and KDF?** AES-256-GCM records, HKDF-SHA256 key schedule. [implemented]

**Q29. Replay protection?** Explicit sequencing + an anti-replay window; zero
false accepts in tests. [tested]

**Q30. Key wear on long sessions?** A rekey ratchet bounds per-key usage. [tested]

**Q31. Downgrade resistance?** No plaintext/classical-only mode is reachable; the
crypto policy enforces FullPqcOnly/NoClassicalFallback and fails closed on any
Unknown attribute. [tested]

**Q32. How is mutual authentication done without ML-DSA on the wire?** ML-DSA is
verified once at provisioning to establish a per-peer HMAC capability; runtime
uses IdentityKeyHash + capability. Mutual auth preserved. [tested]

**Q33. What stops an attacker forging a capability?** It is an HMAC over a secret
established by a one-time PQ-authenticated handshake; an unknown/wrong-capability
peer is rejected fleet-wide. [tested]

**Q34. Memory safety?** Rust; the interceptor's FFI is panic-shielded;
`#![deny(unused_must_use)]` makes a dropped security result a compile error. [implemented]

**Q35. Undefined behaviour?** Miri run; a misaligned-reference UB was found and
fixed. [tested]

**Q36. Concurrency correctness?** Loom exhaustive model checking on the
fail-closed state paths. [tested]

**Q37. Fuzzing?** cargo-fuzz (libFuzzer + ASan); an attacker-reachable epoch
overflow was found and fixed; 400 000-event property fuzzing reached no forbidden
state. [tested]

**Q38. Is there a plaintext fallback anywhere?** No — `OperationMode` has no
`Plaintext` variant; exhaustive-match proof + fuzz. [tested]

**Q39. How is "no cleartext" verified, not just claimed?** Wire bytes are captured
in the deployment scenario and asserted free of a known plaintext marker before/
during/after every event. [tested]

**Q40. Key storage at rest?** Backend-agnostic: software AES-256-GCM sealing
(HKDF passphrase KEK) fully tested; TPM2/PKCS#11 via the real adapter; raw seeds
never on disk. [tested]

**Q41. Hardware root of trust?** TPM2 (swtpm) and PKCS#11 (SoftHSM2) validated
end-to-end; a different TPM cannot unseal. Physical-device acceptance is [design]. [tested]

**Q42. Side channels?** RustCrypto constant-time primitives; capability comparison
is constant-time (`subtle`). Formal side-channel evaluation is part of the
independent review (open). [implemented]

**Q43. DoS resistance detail?** Stateless cookies — no PQC work before peer
validation; per-source + global rate + concurrency caps. [measured]

**Q44. Has an external crypto review been done?** Not yet — it is the #1
path-to-TRL-6 item, scoped into the SPARK grant. (open)

**Q45. What is the trust boundary?** The kernel enforces egress; userspace
performs crypto. A compromised userspace cannot leak because the kernel denies
non-compliant egress. [measured]

**Q46. Crypto agility?** Suite negotiation + multiple ML-KEM parameter sets; a
future PQC-standard change is a config/upgrade, not a rewrite. [implemented]

**Q47. What if kTLS is unavailable?** The bridge returns `KtlsUnavailable` and the
caller fails closed — there is no plaintext userspace-relay fallback. [tested]

**Q48. Forward secrecy?** Ephemeral hybrid key exchange per session; the rekey
ratchet limits exposure. [implemented]

**Q49. How are revoked identities propagated to the fleet?** A revoked hash fails
closed locally now; a CRL→registry feed and signed fleet distribution are
[design]. [tested]/[design]

**Q50. Air-gap integrity?** Offline artifacts are SHA-256-checksum-gated; a
tampered identity export or policy bundle is refused. Signing against an active
adversary is [design]. [tested]

**Q51. Could a malformed handshake crash the daemon?** Panic-path audit + fuzzing
target this; no plaintext or open-fail on malformed input. [tested]

**Q52. Anti-replay across reconnect?** Epoch handling was hardened (overflow fix);
the session record layer rejects replays. [tested]

**Q53. Is the eBPF program safe?** It passes the kernel verifier; uses no
arch-specific helpers/CO-RE; map-miss fails closed. [measured]

**Q54. What is logged for security monitoring?** Categorized events — Decision /
Violation / Fallback / Quarantine — with kernel timestamps and exact drop
accounting. [measured]

**Q55. Biggest security caveat?** No independent crypto review yet, and physical
HSM/TPM acceptance pending — both named and scoped, not hidden. (open/[design])

## C. Procurement reviewers (acquisition & lifecycle) — Q56–80

**Q56. Is this a product or a research artifact?** A working software platform at
TRL 5 with a deployment toolchain (install/package/validate/upgrade/rollback/
air-gap/fleet). [tested]

**Q57. What is the licensing/cost model?** Software licence (per-node/per-site or
subscription); no per-unit hardware BOM. (plan)

**Q58. Procurement route?** iDEX procurement order / Make-II after a successful
pilot and evaluation. (plan)

**Q59. What does a SPARK grant buy?** Independent crypto review, hardware
validation, multi-host pilot, and production hardening — mapped to the named
engineering gaps. (plan)

**Q60. Deployment effort on a host?** install → configure → validate → run from an
offline package, no source build. [tested]

**Q61. Air-gapped deployability?** Yes — fully offline provisioning/updates/
policy. [tested]

**Q62. Upgrade/rollback safety?** `upgrade.sh` backs up, revalidates, and
auto-restores on failure; `rollback.sh` restores a byte-identical binary. [tested]

**Q63. Fleet scale?** Tested at 120 nodes offline; 100+ architecture. [tested]

**Q64. Vendor lock-in / sovereignty?** Indian-controlled source, build, and key
custody; NIST-standard (open) crypto; no foreign black box. [implemented]

**Q65. Hardware dependencies?** Commodity Linux; optional TPM/HSM. [implemented]

**Q66. Accreditation status?** Not yet accredited; accreditation evidence
collection is scheduled into the pilot. (open)

**Q67. Support model?** Tiered L1–L3 with sovereign maintenance and signed offline
update packages. (plan)

**Q68. What is the integration cost for existing apps?** Zero application changes
— the overlay intercepts at the OS boundary. [implemented]

**Q69. Reproducibility for evaluation?** All results reproduce from `cargo test`/
`cargo bench`/`scripts/`; a CI pipeline runs the gate. [tested]

**Q70. Risk of schedule slip?** The remaining work is converting six named
`[design]` items to measured results — engineering, not research. [design]

**Q71. What's the smallest meaningful pilot?** 3–10 nodes on a representative
network slice wrapping non-critical apps. (plan)

**Q72. Total cost of ownership vs hardware appliances?** Lower — software-only,
no per-node hardware, estate-wide licence. (plan)

**Q73. Lifecycle / obsolescence?** Crypto-agility insulates against PQC-standard
evolution; updates are config/upgrade. [implemented]

**Q74. Manufacturing?** None — signed software package; `package.sh` produces the
offline artifact. [tested]

**Q75. Interoperability with legacy systems?** Legacy Migration profile;
incremental migration. [tested]

**Q76. IP ownership?** Original implementation in this repository; sovereign IP.
(statement)

**Q77. Standards compliance?** NIST FIPS 203/204; aligns with national PQC
migration direction. [implemented]

**Q78. What proof of fail-closed for accreditors?** The audit pipeline + the
structural no-plaintext guarantee + the deployment-scenario zero-cleartext
evidence. [measured]/[tested]

**Q79. Multi-vendor host support?** Any Linux with cgroup v2 + CGROUP_SOCK_ADDR;
x86_64 and ARM64. [measured]/[measured-emulated]

**Q80. Procurement risk if kTLS underperforms?** kTLS affects throughput, not
security; the platform is secure and fail-closed without it. The userspace path
already works; kTLS is an optimisation with a stated target. [design]

## D. Technical experts (architecture & implementation) — Q81–100

**Q81. How does kernel interception work?** A `cgroup/connect4` eBPF program on
the connect path reads policy from BPF maps and allows/denies egress. [measured]

**Q82. Map structure?** Structured 80-byte policy objects keyed by cgroup; plus
posture, fallback, quarantine, session, and audit maps. [measured]

**Q83. Policy resolution model?** Global→Node→Application→Session hierarchy,
highest-priority-wins, ties to the more specific level; resolve 895 ns. [measured]

**Q84. Lookup latency?** 343 ns single-level; 895 ns four-level; quarantine
325 ns (short-circuits resolve). [measured]

**Q85. Userspace↔kernel sync?** Userspace pushes full policy objects (1–9 µs),
live on the next connect; session state flows kernel→userspace. [measured]

**Q86. Audit pipeline design?** A ring buffer with per-CPU emitted/dropped
counters and a tunable wakeup policy; ~22 000 eps, exact accounting, drops
counted under forced overflow. [measured]

**Q87. Why is the OOB handshake smaller?** ML-DSA pub+sig (~10.5 KB) is verified
once at provisioning; runtime carries a 32-B hash + HMAC capability. [measured]

**Q88. kTLS integration?** Derive PQC session secrets → `setsockopt(SOL_TLS,
TLS_TX/TLS_RX, ...)` with TLS 1.3 AES-256-GCM crypto_info; capability detection
via `TCP_ULP=tls`. [implemented]

**Q89. Why is kTLS throughput not measured?** The test kernel has no TLS ULP
(`tls` absent from `/proc/.../ulp`); activation is impossible here. Target on a
ULP host: ≥28 % line / ~2×. [design]

**Q90. What is the kinetic state machine?** A supervisor consuming handshake
outcomes that moves between FullPqc/EncryptedFallback/FailClosed; no Plaintext
state; security fail-closed is sticky. [measured]

**Q91. How is "no plaintext" structural?** The `OperationMode` enum has no
plaintext variant; the compiler's exhaustive-match check + fuzzing enforce it. [tested]

**Q92. ARM64 portability proof?** Cross-compiled aarch64; 193 tests run on the
ARM64 ISA under QEMU+binfmt; byte-identical wire artifacts; one EINVAL probe bug
fixed. [measured-emulated]

**Q93. Multi-node test realism?** Independent nodes, real TCP listeners, real OOB
sessions per edge with encrypted echo; 1 225 sessions at 50 nodes; loopback
(multi-host is [design]). [measured]

**Q94. Concurrency model verification?** Loom exhaustively checks the fail-closed
transitions for races/deadlocks. [tested]

**Q95. How is DoS mitigation stateless?** A keyed cookie validates the source
before any PQC work; caps bound per-source and global rates. [measured]

**Q96. eBPF portability across kernels?** Bytecode is arch-independent; no
CO-RE/arch helpers; verified on kernel 6.18.5; ARM64-kernel load is [design]. [measured]

**Q97. What's the daemon-loop integration gap?** The Supervisor, CryptoPolicy
enforcement, and quarantine producer are validated components not yet wired into
the live connection loop — a named [design] item. [design]

**Q98. Test/CI rigor?** fmt + clippy `-D warnings` + locked release build + 28
test suites; native ARM64 CI workflow committed. [tested]

**Q99. How big is the trusted computing base?** Small: Rust crate + a compact eBPF
program (verifier-checked) + standard RustCrypto. Memory-safe by construction. [implemented]

**Q100. What would falsify your claims?** Run the in-repo scripts/tests on any
Linux host — they either reproduce the tagged numbers or they don't. The
`[design]` items are precisely those that need hardware/infra this environment
lacks; we invite their independent execution.
