# Handshake DoS Hardening — Mitigation for Finding C6

**Finding addressed:** C6 — *CPU-exhaustion via handshake flooding*. The hybrid
PQC responder performed expensive asymmetric work for every inbound ClientHello,
before learning anything about the peer, giving an attacker an asymmetric-work
denial-of-service primitive.

**Status:** implemented and tested in this tree. Every number in §5 is a real
outcome of the committed tests in this environment — no fabricated benchmarks.

Labels: **[measured]** produced by a test here · **[implemented]** code exists and
is tested · **[design]** specified, not built in this increment.

---

## 1. Threat addressed

The responder (`crypto::generic::respond`, reached via `over_socket` /
`daemon.rs`) does the costly half of the hybrid handshake the instant a
ClientHello arrives:

- ML-KEM-768 **encapsulation**,
- X25519 ephemeral DH,
- **verify** the initiator's Ed25519 + ML-DSA-65 signatures,
- **generate** the responder's Ed25519 + ML-DSA-65 signatures (ML-DSA-65
  signing is the single most expensive step; the signature alone is 3309 bytes).

A ClientHello costs an attacker almost nothing to emit (it need not be valid —
the cost is paid *before* validation completes for some of these steps, and even
a well-formed-but-untrusted hello forces signature verification). One host can
therefore saturate a responder's CPU with asymmetric crypto. This is the textbook
condition that cookie/retry mechanisms exist to remove.

## 2. Attack model

The adversary can:

- send unlimited ClientHello / handshake messages from one or many sources;
- **spoof** source addresses (cannot receive replies at them);
- **capture** a legitimate handshake and **replay** it;
- send **malformed** / truncated / oversized messages;
- vary all of the above to find an amplification of responder work per attacker
  byte/packet.

The adversary cannot forge the responder's per-epoch HMAC secret (held only in
the responder's memory, rotated) and cannot break the underlying primitives.

**Goal of the mitigation:** make the responder's expensive PQC work
**unreachable** until the peer has proven return-routability and passed cheap,
constant-time admission checks, and **rate-bound** the work a single source can
induce.

## 3. Implementation details

`src/handshake_guard.rs` — a self-contained, pure-CPU admission gate. No new
crates enter the dependency tree: `hmac` and `subtle` were already present
transitively (via `hkdf` and the dalek stack) and are promoted to direct deps.

### 3.1 Two-phase stateless cookie (WireGuard/QUIC-retry in spirit)

```
Phase 0  request(source, now)   -> Cookie         (cost: ONE HMAC, no PQC, no per-conn state)
Phase 1  admit(source, cookie, now) -> Ok | Err    (cost: ≤2 HMAC + window check, no PQC)
         -- only on Ok does the caller run respond()  [the expensive PQC] --
```

**Cookie** = `issued_at(u64 BE) || server_nonce(16) || mac(32)`, 56 bytes, where

```
mac = HMAC-SHA256( secret_epoch , "syntriass-overlay cookie v1" || source || issued_at || server_nonce )
```

- **Stateless issuance.** Issuing a cookie creates **no per-connection state**.
  Validation needs only the responder's rotating secret, so there is no table of
  outstanding challenges to exhaust. **[implemented]**
- **Secret rotation.** The signing secret rotates every `rotation_secs`
  (default 120s); the current **and** previous secret are retained so a cookie
  issued just before a rotation still validates within its `validity_secs`
  (default 60s) window. Secrets are `Zeroizing<[u8;32]>` filled from `OsRng`.
  **[implemented]**

### 3.2 Return-routability ⇒ PQC is gated (requirement 2)

The cookie is returned to the *claimed source address*. An address-spoofing
attacker never receives it and so cannot produce a valid Phase-1 message; their
flood is rejected at the cheap `admit` MAC check, **costing the responder zero
PQC operations**. The caller's contract is explicit: run `respond()` **only**
after `admit` returns `Ok`. **[implemented]** — proven by the PQC-invocation
counter in the tests (§5).

### 3.3 Per-source rate limiting (requirement 3)

A token bucket per source (`rate_capacity` burst, `rate_refill_per_sec` refill)
is consulted at Phase 0. A single source is served at most its burst, then
throttled — bounding the cookies it can obtain and therefore the PQC work it can
later trigger. The source key is `SHA-256(source)[..16]` (fixed-size, so a long
source string cannot bloat the map). The bucket map is capped at `max_sources`
with idle/oldest eviction so a spoofed-source flood cannot grow it without
bound. **[implemented]**

### 3.4 Replay-resistant challenge validation (requirement 4)

- **Freshness:** a cookie older than `validity_secs`, or dated in the future
  (beyond a 2s skew allowance), is rejected (`Expired`). **[implemented]**
- **Authenticity:** the MAC is recomputed and compared in **constant time**
  (`subtle::ConstantTimeEq`) against current then previous secret, so a wrong or
  forged cookie is `BadMac` and the comparison leaks no timing. **[implemented]**
- **One-time use:** each accepted cookie tag is recorded in a consumed-set;
  re-submitting it yields `Replay`. The set is pruned to the validity window and
  hard-capped at `max_replay_entries`, so it is bounded even under a same-second
  burst. **[implemented]**

Validation order is cheapest-first (freshness → MAC → replay) so the bulk of
junk is dropped before the (still cheap) HMAC, and all of it before any PQC.

### 3.5 Failure semantics

Every rejection path returns an `AdmissionError` (`Throttled`, `Expired`,
`BadMac`, `Replay`, `Malformed`) and the caller drops the connection. No path
yields plaintext or partial key material, consistent with the overlay's
fail-closed invariant.

## 4. What is NOT claimed here (honesty boundary)

- **[design]** Wiring the gate into the live `daemon.rs` accept loop (binding the
  cookie to the real kernel-reported peer address and adding the Phase-0
  round-trip to the wire protocol). The gate is implemented and unit/integration
  tested against the real responder, but the daemon still calls `respond()`
  directly; the integration point is specified, not yet committed.
- **[design]** A global (cross-source) concurrency cap / load-shed for the
  aggregate case where millions of *distinct* return-routable sources cooperate
  (a genuine botnet). Per-source limiting bounds each source; an aggregate cap is
  the complementary control (see residual risks).
- No timing benchmark of the responder under load is claimed — this sandbox is
  not representative hardware, so a wall-clock "requests/sec sustained" figure
  would be fabricated. The evidence is **operation counts** (PQC invocations),
  which are hardware-independent and decisive for the asymmetric-work property.

## 5. Validation evidence

Reproduce:

```
cargo test --test handshake_dos_tests -- --nocapture
cargo test --lib handshake_guard
```

**Unit tests** (`src/handshake_guard.rs`, 12 tests, **[measured]** all pass):
happy path; cookie wire round-trip; forged cookie → `BadMac`; cookie bound to
source (does not transfer); replay → `Replay`; expired/future → `Expired`;
malformed bytes → parse `None`; single-source burst throttled to capacity;
bucket refill over time; secret rotation keeps previous epoch valid; source map
bounded under a 10 000-source spoof flood.

**Integration tests against the real PQC responder**
(`tests/handshake_dos_tests.rs`, 6 tests, **[measured]** this run):

| Scenario | Attacker volume | Real PQC `respond()` invocations | Other |
|---|---:|---:|---|
| Legitimate flood, 1 source, rate 20 burst / 10 s⁻¹ | 1 000 attempts | **20** (= burst budget) | 980 throttled |
| Invalid (forged-cookie) flood | 50 000 | **0** | 50 000 rejected |
| Spoofed-source flood (no return-routability) | 20 000 sources | **0** | source map ≤ cap |
| Replayed handshake | 10 000 submissions | **1** | 9 999 `Replay` |
| Malformed messages (6 lengths × 1 000) | 6 000 | **0** | no panic |
| Mixed blended assault + 3 honest sources | 100 000 nuisance | **15** (only honest admits) | sources ≤ 512, replay ≤ 1024 |

Decisive properties demonstrated:

1. **Invalid, spoofed, and malformed floods drive the PQC responder exactly
   zero times** — the asymmetric-work primitive is removed.
2. **A replayed handshake triggers PQC at most once** — replays cannot multiply
   work.
3. **A legitimate flood is capped at the per-source rate budget**, not amplified
   per packet.
4. **Bounded memory** — the source and replay structures never exceed their
   configured caps under 6-figure floods.

## 6. Residual risks

- **R1 — Distributed return-routable flood (botnet).** Per-source limiting does
  not cap *aggregate* admitted load from millions of distinct, genuinely
  reachable sources. Mitigation (**[design]**): a global concurrency/PQC-rate cap
  with load-shed, plus deployment behind the existing eBPF/cgroup ingress
  controls. Tracked, not closed.
- **R2 — Cookie issuance is itself work.** Phase 0 costs one HMAC + one RNG draw.
  A spoofed flood still forces that per packet. HMAC-SHA256 is ~3–4 orders of
  magnitude cheaper than the ML-DSA-65 signing it replaces, and the source map is
  capped, so the amplification is removed; the residual constant-cost reflection
  is the standard cookie trade-off and should sit behind kernel-level rate
  controls for line-rate floods.
- **R3 — Clock dependence.** Freshness uses a caller-supplied coarse clock. A
  badly skewed clock widens/narrows the validity window. The 2s future-skew
  allowance and current+previous secret retention bound the impact; a monotonic
  source is assumed at deployment.
- **R4 — Not yet on the live wire.** Until §4's daemon integration lands, these
  guarantees hold for the gate in isolation and against the real responder in
  tests, not yet for the fielded `daemon.rs` path.

## 7. Test ↔ requirement traceability

| Requirement | Test(s) |
|---|---|
| 1. Stateless cookie | `cookie_round_trips_through_wire`, `secret_rotation_keeps_previous_epoch_valid` |
| 2. PQC gated on return-routability | `invalid_handshake_flood_triggers_zero_pqc`, `spoofed_source_flood_triggers_zero_pqc`, `cookie_bound_to_source_does_not_transfer` |
| 3. Per-source rate limiting | `rate_limiter_throttles_a_single_source_burst`, `rate_limiter_refills_over_time`, `legitimate_flood_is_capped_by_rate_budget_not_per_packet` |
| 4. Replay-resistant challenge | `replayed_cookie_is_rejected`, `replayed_handshake_triggers_pqc_at_most_once`, `expired_cookie_is_rejected`, `future_dated_cookie_is_rejected` |
| 5. Flood / invalid / replay / malformed / exhaustion | the six `handshake_dos_tests` + `source_map_stays_bounded_under_spoofed_flood` |
