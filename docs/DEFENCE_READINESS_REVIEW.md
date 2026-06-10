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
| **C6** | Handshake-flood CPU exhaustion: PQC work performed before peer validation | High | **Mitigated (gate implemented + tested); live-wire integration [design]** | `docs/HANDSHAKE_DOS_HARDENING.md`; `src/handshake_guard.rs`; `tests/handshake_dos_tests.rs` |
| (PQC-2) | Long-session key-wear, no anti-replay/rekey on lossy links | Med | **Mitigated (record layer implemented + tested)** | `docs/PQC_PROTOCOL_SPEC.md §4`; `src/crypto/session.rs`; `tests/session_hardening_tests.rs` |
| C1–C5, C7+ | Universal interception, identity lifecycle, resilience (`tc netem`), sovereign/ARM, formal fail-closed (Miri/Loom/fuzz) | — | **Open / tracked** | Not runnable in the current sandbox; scoped as host-only / future increments (see §4) |

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

### 2.2 What was implemented

A two-phase **stateless-cookie admission gate** (`src/handshake_guard.rs`) that
makes the PQC path unreachable until the peer proves return-routability and
passes cheap, constant-time checks, with per-source rate limiting and replay
resistance. Full design in `docs/HANDSHAKE_DOS_HARDENING.md`. Key points:

- **Return-routability before PQC.** Cookie = `HMAC-SHA256(rotating secret,
  label ‖ source ‖ issued_at ‖ nonce)`, issued statelessly (one HMAC, no
  per-connection state) and bound to the source. The caller runs `respond()`
  **only** after `admit()` returns `Ok`. **[implemented]**
- **Per-source token-bucket rate limiting**, with the source-key and bucket-map
  size both bounded (no memory-exhaustion side door). **[implemented]**
- **Replay resistance**: freshness window + constant-time MAC
  (`subtle::ConstantTimeEq`) + one-time consumed-tag set (pruned + capped).
  **[implemented]**
- **No new dependencies** (`hmac`, `subtle` were already transitive).

### 2.3 Evidence (reproducible)

```
cargo test --lib handshake_guard            # 12 unit tests
cargo test --test handshake_dos_tests -- --nocapture   # 6 tests vs the REAL responder
```

Counting **real** `crypto::generic::respond()` (ML-KEM + X25519 + ML-DSA-65)
invocations, **[measured]** this run:

| Attack | Volume | PQC invocations |
|---|---:|---:|
| Forged-cookie flood | 50 000 | **0** |
| Spoofed-source flood | 20 000 sources | **0** |
| Malformed messages | 6 000 | **0** |
| Replayed handshake | 10 000 submissions | **1** |
| Legitimate flood (rate 20/10s⁻¹) | 1 000 attempts | **20** (rate-capped) |
| Mixed assault + 3 honest sources | 100 000 nuisance | **15** (honest only) |

The asymmetric-work primitive is removed: junk and spoofed floods do **zero** PQC;
replays do at most one; legitimate load is capped to the per-source budget, not
amplified per packet. Memory stays within configured caps under six-figure floods.

### 2.4 Residual risk and revised severity

Residual risks (detailed in `docs/HANDSHAKE_DOS_HARDENING.md §6`):

- **R1 distributed return-routable (botnet) flood** — per-source limiting does
  not cap aggregate admitted load; a global concurrency/PQC-rate cap is **[design]**.
- **R2 cookie issuance is still a per-packet HMAC** — ~3–4 orders of magnitude
  cheaper than the ML-DSA-65 signing it replaces; line-rate floods should sit
  behind kernel/eBPF ingress controls.
- **R4 not yet wired into `daemon.rs`** — guarantees proven for the gate and
  against the real responder in tests; live-wire integration is **[design]**.

**Revised severity: High → Low–Medium**, contingent on:
1. wiring the gate into the live daemon accept loop (the **[design]** item), and
2. adding the aggregate concurrency cap (R1).

Until (1) lands, C6 is **"mitigation built and validated, not yet on the fielded
path"** — an honest, defensible state for technical review, with a clear, small
closeout path. It is **not** marked Closed.

---

## 3. Delivered hardening increments (this branch)

1. **PQC record-layer hardening (PQC-2).** Explicit sequencing, IPsec/DTLS-style
   sliding-window anti-replay, forward-secret rekey ratchet, and session
   lifecycle limits over the real handshake. Measured end-to-end at 10/20/30/45%
   loss: 100% of delivered records open exactly once, 100% of replays rejected,
   zero false accepts. See `docs/PQC_PROTOCOL_SPEC.md §4`.
2. **Handshake DoS gate (C6).** This document, §2.

Both are pure-Rust, fully tested in-sandbox, and add no packages to the
dependency tree.

---

## 4. Honest boundary — not proven in the current environment

These require provisioned hardware/toolchains absent from this sandbox and are
tracked as host-only or future increments; they are **[design]** here and must
not be read as validated:

- **Universal eBPF interception** across glibc/musl/static/Go/containers/K8s
  (no `bpf-linker`/`tc`/CAP_BPF here).
- **`tc netem` 10/20/30/45% loss** at the kernel qdisc level (the record-layer
  loss numbers above use an in-process model, clearly labelled as such).
- **Identity lifecycle** (enrolment/rotation/revocation/expiry, TPM2/PKCS#11/HSM,
  air-gap provisioning).
- **Sovereign ARM64** hardware validation.
- **Formal fail-closed assurance** (Miri/Loom/fuzzing/property-model-checking).

---

## 5. Reproduce everything

```
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo build --release --locked
cargo test --release --locked
cargo test --test handshake_dos_tests --test session_hardening_tests -- --nocapture
```

All gates pass in this environment at the current HEAD.
