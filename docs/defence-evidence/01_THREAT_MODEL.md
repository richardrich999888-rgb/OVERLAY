# 1. Threat Model

Tags per `00_INDEX.md`. This model states the adversary, the assets, the attack
surface, and each threat mapped to its mitigation and evidence.

## 1.1 Adversary

A capable, nation-state-grade adversary who can:

- **Observe and record** all ciphertext on the link, for later cryptanalysis,
  including with a future cryptographically-relevant quantum computer ("harvest
  now, decrypt later").
- **Actively manipulate** the network: drop, reorder, duplicate, inject, and
  modify packets; spoof source addresses; mount man-in-the-middle.
- **Degrade** the link: jamming/EW producing 10–45 %+ packet loss, latency,
  jitter, and intermittent connectivity.
- **Flood** the responder to exhaust CPU (asymmetric-work DoS).
- **Supply arbitrary bytes** to every parser and protocol message.
- **Co-reside** on an endpoint at lower privilege and attempt to bypass the
  overlay (e.g. egress via a static binary, Go, or a raw syscall that an
  LD_PRELOAD shim cannot see).

Out of scope (stated for honesty): a fully compromised, root-privileged endpoint
that controls the kernel/eBPF layer itself; supply-chain compromise of the build
toolchain; physical extraction from a powered, unlocked device.

## 1.2 Assets

| Asset | Protection goal |
|---|---|
| Application plaintext | Confidentiality + integrity on the wire (never emitted in clear) |
| Long-term identity keys (Ed25519 + ML-DSA-65) | Secrecy; lifecycle-managed (enrol/rotate/revoke/expire) |
| Session keys | Forward secrecy; bounded lifetime; zeroized |
| Responder CPU/availability | Resist asymmetric-work DoS |
| Interception completeness | Every egress connection is seen/enforced, regardless of runtime |

## 1.3 Attack surface

- The **wire**: handshake messages, sealed records, fallback exchange, admission
  cookies, revocation lists.
- The **egress path**: `connect()` from any process/runtime on the host.
- The **control daemon**: accept loop, parsers, shared state under concurrency.
- The **config/identity**: peer trust material, policy.

## 1.4 Threats → mitigations → evidence

| # | Threat | Mitigation | Tag | Evidence |
|---|---|---|---|---|
| T1 | Harvest-now-decrypt-later (quantum) | Hybrid X25519 **+ ML-KEM-768/1024** KEM; AES-256-GCM (128-bit PQ) | [tested] | `crypto::*`, `PQC_PROTOCOL_SPEC.md §2–3` |
| T2 | MITM / impersonation | Mutual **dual-signature** auth (Ed25519 **+ ML-DSA-65**); identity pinning | [tested] | `untrusted_client_identity_rejected`, `unauthenticated_client_hello_rejected` |
| T3 | Downgrade / strip-PQC | No non-PQC suite exists; suite bound into transcript + signatures; fallback decided from **local** posture | [tested] | `binding_tests::*`, `fallback::DowngradeDetected` |
| T4 | Replay of records | Sequenced records + IPsec-style 64-window anti-replay (commit after tag verify) | [tested]/[measured] | `session_hardening_tests`, loss-ladder table |
| T5 | Tamper / forge a record | AEAD with header bound as AAD; any mutation ⇒ `Err` | [tested] | `i2_any_tamper_fails_closed` (20 000 cases) |
| T6 | Key-wear / long-session compromise | Forward-secret rekey ratchet; lifecycle caps; zeroize | [tested] | `crypto::session` rekey tests |
| T7 | Handshake-flood CPU exhaustion (C6) | Stateless-cookie admission gate (return-routability) + per-source + global rate/concurrency caps, on the live daemon path | [tested]/[measured] | `HANDSHAKE_DOS_HARDENING.md`; PQC-invocation counts |
| T8 | Spoofed-source / distributed flood | Cookie bound to kernel peer-IP; global PQC-rate + in-flight caps | [measured] | forged 50k→0 PQC; distributed 5 000 src→25 (global burst) |
| T9 | Crash / hang on adversarial input (fail-open) | Parser robustness + panic audit; Miri; fuzzing | [measured] | 50k property inputs; cargo-fuzz 10.8M+ runs; **1 overflow fail-open found & fixed** |
| T10 | Plaintext leakage via side surfaces | Debug redaction, no keys on wire, no error reflection, no PSK on wire | [tested] | `leakage_analysis.rs` L1–L4 |
| T11 | Egress bypass via non-libc runtime | **eBPF `cgroup/connect4`** below libc; observes+denies | [measured] | 7/7 runtimes incl. static/Go/musl/direct-syscall; EPERM deny |
| T12 | Availability under jamming | Encrypted PSK fallback (no plaintext path) under degraded posture | [tested] | `crypto::fallback`, chaos tests |
| T13 | Compromised identity in the field | Credential lifecycle: revocation (signed CRL + freshness), expiry, rotation | [tested] | `identity_lifecycle_tests` |
| T14 | Concurrency races in the daemon | Single-CS permit accounting; poison fail-closed; **Loom exhaustive** | [measured] | `concurrency_stress.rs`, `loom_model.rs` |

## 1.5 Residual threat exposure (honest)

- **TX1 [design]** IPv6/UDP egress is not yet intercepted (`connect4` only);
  `connect6`/`sendmsg4` are symmetric and specified.
- **TX2 [design]** A root-compromised endpoint can detach eBPF — the enforcement
  agent's privilege is the trust boundary, by design.
- **TX3 [design]** Real-link (`tc netem`) loss/jitter is modelled in-process, not
  yet measured on a kernel qdisc.
- **TX4 [design]** Hardware key extraction resistance (TPM/HSM) is not yet in
  effect; the ML-DSA key is software-resident pending PQC-capable HSMs.

These appear in `05_RISK_REGISTER.md` and `08_RESIDUAL_RISK_REPORT.md`.
