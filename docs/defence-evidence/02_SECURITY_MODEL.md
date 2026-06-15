# 2. Security Model

Tags per `00_INDEX.md`. Deep dive: `../PQC_PROTOCOL_SPEC.md`.

## 2.1 Security guarantees (and their status)

| Guarantee | Statement | Tag |
|---|---|---|
| G1 Post-quantum confidentiality | Session keys derived from `X25519_ss ‖ ML-KEM_ss` via HKDF-SHA256; AEAD = AES-256-GCM. An attacker must break **both** the PQ and classical KEM. | [tested] |
| G2 Mutual PQ authentication | Both peers sign the transcript with **Ed25519 and ML-DSA-65**; both verified. Forgery requires breaking both. | [tested] |
| G3 Downgrade resistance | Only PQ suites are negotiable; suite is bound into the transcript hash and the signatures; fallback is chosen from local posture, never the wire. | [tested] |
| G4 Forward secrecy | Per-session ephemeral KEM keys; intra-session one-way HKDF rekey ratchet; old keys zeroized. | [tested] |
| G5 Anti-replay | Explicit per-record sequence + 64-wide sliding window; window advances only **after** the AEAD tag verifies. | [tested]/[measured] |
| G6 Integrity / fail-closed | Any tampered/forged/stale/expired record yields `Err`, never plaintext. | [tested]/[measured] |
| G7 No cleartext on the wire | Structural: the availability-posture type has **no `Plaintext` variant**; every error path returns `Err`. | [tested]/[measured] |
| G8 Availability under jamming | Encrypted PSK fallback keeps traffic confidential (AES-256) when the PQC control plane is unreachable — never plaintext. | [tested] |
| G9 Anti-DoS | PQC work is unreachable until a return-routability cookie validates; per-source + global caps bound aggregate work. | [tested]/[measured] |
| G10 Universal enforcement | Egress interception at the kernel `connect` hook, below libc — superset of LD_PRELOAD coverage; fail-closed deny. | [measured] |

## 2.2 Cryptographic constructions [implemented]/[tested]

| Role | Primitive | Parameters |
|---|---|---|
| KEM (ephemeral) | ML-KEM | 768 (`0x01`) / 1024 (`0x02`) |
| KEM (classical hybrid) | X25519 | — |
| Signature (PQ) | ML-DSA | 65 (FIPS 204) |
| Signature (classical hybrid) | Ed25519 | — |
| KDF | HKDF-SHA256 | transcript- and suite-bound `info` |
| AEAD | AES-256-GCM | 96-bit nonce from seq; tag binds the record header |
| Cookie MAC | HMAC-SHA256 | rotating per-epoch secret; constant-time compare (`subtle`) |

Key schedule, transcript binding, and the record layer are specified with
test↔claim traceability in `../PQC_PROTOCOL_SPEC.md`.

## 2.3 Trust boundaries

```
 [ workload process ]   (untrusted; any runtime)
        | connect()
 ======= kernel cgroup/connect4 eBPF =======   <-- TRUST BOUNDARY 1 (enforcement)
        | event (ringbuf) / allow|deny
 [ privileged control daemon ]                 <-- TRUST BOUNDARY 2 (holds identity)
        | PQC handshake over the socket
 [ peer control daemon ] --- pinned/credential-verified identity ---
        | derived keys
 ======= kernel TLS (kTLS) =======             <-- data-plane encryption in kernel
```

- **TB1** The eBPF agent is privileged (`CAP_BPF`+`CAP_SYS_ADMIN`); workloads are
  not. This is the intended asymmetry. [design for deployment]
- **TB2** The control daemon holds identity keys (software, zeroizing; or a
  `HybridSigner` hardware backend [design]). [implemented]
- **TB3** Peer trust is established by pinned keys today, or by a CA-signed
  credential (`identity` module) verified offline. [tested]

## 2.4 Fail-closed invariants (load-bearing)

| Invariant | Enforcement | Tag |
|---|---|---|
| Never emit application plaintext | No `Plaintext` posture; AEAD-only seal; canary property test | [tested]/[measured] |
| Never panic on adversarial input | Panic-path audit; parser robustness; fuzzing | [measured] |
| Any crypto/admission error ⇒ drop | All error enums return `Err`; `#![deny(unused_must_use)]` | [implemented]/[tested] |
| kTLS install failure ⇒ teardown | `shutdown(SHUT_RDWR)` + `close` on any kTLS error | [implemented] |
| Concurrency cap never exceeded | Single critical-section permit; Loom-proven | [measured] |
| Poisoned lock ⇒ fail-closed error | Production `.lock()` maps poison → `Err` | [tested] |

## 2.5 Known cryptographic boundaries (honest)

- **B1 [design]** The hybrid identity's ML-DSA private key is **software-resident**
  (zeroizing). TPM2/most HSMs lack ML-DSA, so hardware can protect only the
  Ed25519 half today (the hybrid still requires forging both). See
  `../IDENTITY_LIFECYCLE.md §4`.
- **B2 [design]** Constant-time review of the full responder under a timing
  adversary is partial; `subtle` is used for cookie compare, and the AEAD/KEM
  crates are constant-time, but an end-to-end timing audit is not complete.
- **B3 [design]** Formal (machine-checked) proofs of the protocol are not claimed;
  assurance is via property/fuzz/Loom/Miri, not a proof assistant.
