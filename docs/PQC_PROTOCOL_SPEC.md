# SYNTRIASS Overlay — PQC Protocol Specification

**Status:** working specification, kept in lock-step with the implementation.
Every construction below maps to committed code and to a test that exercises it.
Claims are labelled **[measured]** (a test/benchmark produces the number here),
**[implemented]** (code exists and is tested), or **[design]** (specified, not yet
built in this tree). No number in this document is fabricated.

Audience: DRDO cryptographers, Linux kernel maintainers, red-team reviewers,
procurement engineers.

---

## 1. Scope and threat model (summary)

SYNTRIASS Overlay establishes a mutually-authenticated, post-quantum-hybrid
secure channel between two endpoints that already trust each other's long-term
identity keys (pinned, not PKI-discovered). The full threat model lives in
`docs/THREAT_MODEL.md`; the cryptographically relevant assumptions are:

- **Adversary:** an on-path active attacker with the ability to drop, reorder,
  duplicate, inject, and modify packets, and to record traffic for later
  ("harvest-now-decrypt-later") cryptanalysis including a future CRQC
  (cryptographically-relevant quantum computer).
- **Trust anchor:** each peer is provisioned out-of-band with the other peer's
  Ed25519 + ML-DSA-65 public identity keys. Identity discovery/PKI is **[design]**
  (see `docs/IDENTITY_LIFECYCLE.md`, not in this increment).
- **One hard invariant:** the overlay never emits application plaintext on the
  wire. This is structural — the availability-posture type has no `Plaintext`
  variant (`src/kernel_native.rs::AvailabilityPosture`), and every record-layer
  error path returns `Err`, never cleartext.

---

## 2. Cryptographic primitives

| Role | Primitive | Parameter set | Crate |
|---|---|---|---|
| KEM (ephemeral) | ML-KEM | 768 (suite `0x01`) / 1024 (suite `0x02`) | `ml-kem` 0.2.3 |
| KEM (classical hybrid) | X25519 | — | `x25519-dalek` |
| Signature (PQ) | ML-DSA | 65 | `ml-dsa` 0.1.1 |
| Signature (classical hybrid) | Ed25519 | — | `ed25519-dalek` |
| KDF | HKDF-SHA256 | — | `hkdf`, `sha2` |
| AEAD | AES-256-GCM | 96-bit nonce, 128-bit tag | `aes-gcm` |

**Hybrid rationale.** Both the key exchange and the authentication are
**hybrid**: an attacker must break *both* the post-quantum primitive *and* the
classical one to defeat the channel. ML-KEM/ML-DSA protect against a future
CRQC; X25519/Ed25519 protect against a (hypothetical) structural break in the
NIST PQ primitives. Shared-secret material is concatenated as
`X25519_ss || ML-KEM_ss` and fed to HKDF, so the derived keys are at least as
strong as the stronger input. **[implemented]** — `src/crypto/generic.rs`.

**AES-256 under Grover.** AES-256-GCM gives ~128-bit post-quantum security
against Grover search, which is the symmetric target NIST associates with
Category 5. **[implemented]**

---

## 3. Handshake

Two messages, mutually authenticated, transcript-bound.

```
Initiator (client)                                   Responder (server)
------------------                                   ------------------
ephemeral X25519 (x_c), ML-KEM (dk_c, ek_c)
ClientHello =
  x_c.pub || ek_c
  || ed25519_pub_c || mldsa65_pub_c
  || Sig_c( "client identity v1" || suite || above )
                         ---- ClientHello ---->
                                                     verify ed25519/mldsa pubs == pinned peer
                                                     verify Sig_c (Ed25519 AND ML-DSA-65)
                                                     ephemeral X25519 (x_s)
                                                     (ct, ss_mlkem) = Encap(ek_c)
                                                     ss_x = X25519(x_s, x_c.pub)
                                                     ServerHello =
                                                       x_s.pub || ct
                                                       || ed25519_pub_s || mldsa65_pub_s
                                                       || Sig_s( "server identity v1"
                                                                 || suite || ClientHello || above )
                         <--- ServerHello -----
verify pubs == pinned peer
verify Sig_s (Ed25519 AND ML-DSA-65)
ss_mlkem = Decap(dk_c, ct)
ss_x = X25519(x_c, x_s.pub)
```

Both sides then compute identical session keys:

```
IKM        = ss_x || ss_mlkem
transcript = SHA256( "transcript hash v1" || suite || ClientHello || ServerHello )
info       = "syntriass-overlay v3 suite=" || suite || transcript
OKM(64)    = HKDF-SHA256(salt=∅, IKM, info)
c2s_key    = OKM[0..32]      s2c_key = OKM[32..64]
```

The initiator uses `c2s` for TX / `s2c` for RX; the responder is mirrored.
**[implemented]** — `derive()` in `src/crypto/generic.rs`; round-trip and
agility coverage in `crypto::verification_tests`.

### 3.1 Authentication and binding properties

- **Mutual auth, dual-signature.** Each side signs with **both** Ed25519 and
  ML-DSA-65; the peer verifies **both** (`verify_peer_signatures`). A forgery
  requires breaking both schemes. **[implemented]**
- **Identity pinning.** The responder/initiator reject any hello whose embedded
  identity public keys are not byte-equal to the pinned peer keys
  (`verify_peer_public_keys`) — tested by `untrusted_client_identity_rejected`.
  **[implemented]**
- **Transcript binding.** The session keys depend on the SHA-256 of the full
  transcript *and* the suite id (folded into HKDF `info`). The server's signature
  also covers the ClientHello, so the two messages are cryptographically
  stapled. A single flipped byte yields non-matching keys → AEAD fails closed.
  Tested by `binding_tests::suite_id_changes_derived_keys`,
  `unauthenticated_client_hello_rejected`. **[implemented]**

### 3.2 Downgrade resistance

There is **no** non-PQC or legacy cipher in the negotiable set
(`CipherSuite` has exactly `NistStandard768` and `NistStandard1024`; no
"classical-only" or "plaintext" variant exists). The suite is bound into the
transcript and signatures, so an attacker cannot strip the PQC layer or force a
weaker suite without invalidating the signatures. The fallback decision (§5) is
taken from **local** policy, never from a wire-controlled flag, which is what
makes it downgrade-resistant. **[implemented]** — tested across the suite-id
binding tests and `src/crypto/fallback.rs::DowngradeDetected`.

### 3.3 Forward secrecy (handshake)

Every session uses fresh ephemeral X25519 and ML-KEM keys; the long-term
identity keys sign but never derive traffic keys. Compromise of an identity key
does not retroactively decrypt recorded sessions (it permits future
impersonation only). **[implemented]**

### 3.4 Measured handshake cost

From the committed benchmark harness on this sandbox host (4 vCPU, software
only; **not** representative of fielded ARM/x86 hardware):

| Metric | Value | Source |
|---|---|---|
| Handshake e2e latency, post identity-cache | median ~2.3 ms, P99 ~3.8 ms | **[measured]** `BENCHMARKS.md` |
| ClientHello+ServerHello envelope (suite 768) | 13.06 KB | **[measured]** |
| KEM-only envelope projection (suite 768) | ~2.3 KB — **UNAUTHENTICATED projection, not a shippable mode** | **[measured/labelled]** |

---

## 4. Hardened record layer  *(this increment)*

The handshake output (`SessionKeys`) is sufficient for a strictly in-order,
lossless transport — e.g. the kTLS bridge, where the kernel owns sequencing.
Over a lossy, reorderable, hostile tactical link it is not. `SecureSession`
(`src/crypto/session.rs`) adds four properties **with no new dependencies** and
**no change to the handshake or the kTLS export path**.

### 4.1 Record format

```
Record = epoch(u32 BE) || seq(u64 BE) || AES-256-GCM( nonce=seq, aad=header, pt )
         \_________ 12-byte header ________/
```

- The 12-byte header is cleartext **and** is the AEAD associated data, so it is
  authenticated: an attacker cannot move a ciphertext to a different
  `(epoch, seq)` slot without the tag failing.
- The 96-bit GCM nonce is `0x00000000 || seq` (big-endian in the low 8 bytes).
  Each rekey installs a fresh key (§4.3), and `seq` is unique within an epoch, so
  **no `(key, nonce)` pair is ever reused** — the AES-GCM catastrophic-reuse
  condition cannot occur. **[implemented]**

### 4.2 Sliding-window anti-replay

`AntiReplayWindow` is an IPsec/DTLS-style 64-record sliding window (RFC 6479 in
spirit). A record is accepted iff its `seq` is newer than the highest seen, or
within 64 of it and not previously accepted. The window is advanced **only after
the AEAD tag verifies**, so a forged/garbage header can never poison replay
state.

- Replays rejected: `SessionError::Replay`. **[implemented/tested]**
- Stale (older than the window): `SessionError::Replay`. **[implemented/tested]**
- Reorder/loss within the window: tolerated. **[implemented/tested]**

**[measured]** end-to-end over the real handshake, seeded/reproducible
(`tests/session_hardening_tests.rs::lossy_reordered_replayed_channel_holds_invariants`),
bounded reorder (jitter ≤12 ≪ window 64):

| Injected loss | Distinct delivered | Accepted exactly once | Replays injected | Replays rejected |
|---:|---:|---:|---:|---:|
| 10% | 448 | 448 | 62 | 62 |
| 20% | 389 | 389 | 73 | 73 |
| 30% | 343 | 343 | 41 | 41 |
| 45% | 277 | 277 | 49 | 49 |

Interpretation: at every loss rate, **100% of delivered records open to their
exact plaintext exactly once, and 100% of replays are rejected** — zero false
accepts, zero leaks. (Loss here is in-process record drop, not a real `netem`
qdisc; the kernel-level `tc netem` validation is a separate, host-only track —
**[design]** in `docs/RESILIENCE.md`.)

### 4.3 Forward-secret rekey ratchet

`SecureSession::rekey()` advances both directions via a one-way ratchet:

```
key_{epoch+1} = HKDF-SHA256( salt=∅, IKM=key_epoch, info="syntriass-overlay rekey v1" || (epoch+1) )
```

The pre-ratchet key bytes are overwritten in place (the buffer is `Zeroizing`).
Because HKDF is one-way, an adversary who compromises `key_{epoch+1}` **cannot**
derive `key_epoch` or any earlier key, and therefore cannot decrypt traffic from
earlier epochs. This adds *intra-session* forward secrecy on top of the
*per-session* forward secrecy of §3.3.

To survive a rekey on a reordering link, the receiver retains the previous
epoch's receive direction (and its replay window) for **exactly one** step:
in-flight epoch-`N` records still open after the peers advance to `N+1`; an
epoch two steps behind is rejected (`EpochMismatch`). At the following rekey the
grace epoch is dropped and its key zeroized — the point at which forward secrecy
for that epoch becomes unconditional. **[implemented/tested]** —
`in_flight_record_opens_across_one_rekey`, `record_two_epochs_old_is_rejected`,
`long_session_rekeys_and_preserves_forward_secret_epochs`.

> **Boundary [design]:** rekey is currently a *coordinated* operation (both peers
> call `rekey()`); the in-band **KeyUpdate** signalling message that lets one peer
> trigger the other's ratchet mid-stream is specified but not yet wired. The
> grace-epoch machinery that makes it safe is already implemented and tested.

### 4.4 Lifecycle limits

`SessionLimits` enforces both soft and hard bounds:

| Bound | Default | Effect |
|---|---|---|
| `rekey_after_records` | 2²⁰ | soft → `NeedsRekey` (operable, should ratchet) |
| `rekey_after_bytes` | 2³⁰ (1 GiB) | soft → `NeedsRekey` |
| `max_records` | 2³⁴ | hard → `Expired`, fails closed |
| `max_bytes` | 2⁴⁰ (1 TiB) | hard → `Expired`, fails closed |
| `max_age` | 24 h | hard → `Expired`, fails closed |

Past any hard cap, `seal` and `open` both return `SessionError::Expired` — there
is no degraded plaintext mode. The hard data caps sit well under the AES-GCM
single-key safety limit, bounding key-wear. **[implemented/tested]** —
`hard_record_cap_expires_session`, `age_cap_expires_session`,
`soft_threshold_flags_needs_rekey_without_failing`.

---

## 5. Degraded encrypted fallback (availability under jamming)

When the asymmetric control plane is unavailable (e.g. sustained EW jamming
prevents completing the ~13 KB handshake), peers that share a pre-provisioned
PSK can still establish an **encrypted** channel via `derive_fallback_session`
(`src/crypto/fallback.rs`). Properties:

- AES-256-GCM from `HKDF(PSK, transcript(client_nonce, server_nonce))`; domain
  id `0xFF` (reserved — `CipherSuite::from_id(0xFF) == None`) so fallback keys can
  never collide with a real suite. **[implemented]**
- PSK authenticates: an attacker without it derives a different key and AEAD open
  fails. **[implemented]**
- **Tradeoff, stated honestly:** the PSK path has **no forward secrecy** (PSK
  reuse). That is the documented price of availability under jamming. It **never**
  sends cleartext. The hardened record layer (§4) composes on top of a fallback
  session exactly as it does on a PQC session.
- **Downgrade-resistant:** the choice to use fallback is taken from local posture
  (`pqc_control_available()`, read from local config/heartbeat), never from a
  wire flag, so an on-path attacker cannot force a healthy node into fallback.
  **[implemented]** — `fallback::DowngradeDetected`.

---

## 6. What is NOT yet proven in this tree (honesty boundary)

- **In-band KeyUpdate signalling** — §4.3 boundary. **[design]**
- **Kernel `tc netem` loss validation** — §4.2 uses an in-process loss model;
  real qdisc validation is host-only. **[design]** (`docs/RESILIENCE.md`)
- **Identity lifecycle / PKI / TPM2 / HSM / air-gap provisioning.** **[design]**
- **Constant-time review of the handshake responder** under a timing adversary.
  **[design]** (security-hardening track)
- **Formal anti-replay proof (Loom/Miri).** The window is unit- and
  property-tested but not model-checked. **[design]** (fail-closed track)

---

## 7. Test ↔ claim traceability

| Claim | Test |
|---|---|
| Hybrid handshake round-trips, both suites | `crypto::verification_tests::agility_loop_all_suites` |
| Identity pinning rejects untrusted peer | `untrusted_client_identity_rejected` |
| Tamper/forgery fails closed | `tampered_record_rejected`, `unauthenticated_client_hello_rejected` |
| Suite/transcript binding | `binding_tests::suite_id_changes_derived_keys` |
| Record header is authenticated AAD | `session::tests::header_is_authenticated_aad` |
| Replay rejected | `session::tests::replay_is_rejected` |
| Reorder within window tolerated | `session::tests::reordering_within_window_is_tolerated` |
| Stale (past-window) rejected | `session::tests::record_older_than_window_is_rejected` |
| Forward-secret rekey + grace epoch | `session::tests::in_flight_record_opens_across_one_rekey` |
| Two-epochs-old rejected | `session::tests::record_two_epochs_old_is_rejected` |
| Hard/soft lifecycle limits | `session::tests::hard_record_cap_expires_session`, `age_cap_expires_session` |
| Loss 10/20/30/45% end-to-end invariants | `session_hardening_tests::lossy_reordered_replayed_channel_holds_invariants` |
| Long session rekeys | `session_hardening_tests::long_session_rekeys_and_preserves_forward_secret_epochs` |

Reproduce all of the above:

```
cargo test --release --locked
cargo test --test session_hardening_tests -- --nocapture   # prints the loss table
```
