# Handshake DoS Hardening — Mitigation for Finding C6

**Finding addressed:** C6 — *CPU-exhaustion via handshake flooding*. The hybrid
PQC responder performed expensive asymmetric work for every inbound ClientHello,
before learning anything about the peer, giving an attacker an asymmetric-work
denial-of-service primitive.

**Status:** **on the real daemon execution path** and tested end-to-end. The gate
runs for every connection the daemon accepts (`src/bin/daemon.rs` →
`over_socket::establish_and_bridge_gated`), with per-source *and* global
(aggregate rate + concurrency) limits. Every number in §5 is a real outcome of
the committed tests in this environment — no fabricated benchmarks.

Labels: **[measured]** produced by a test here · **[implemented]** code exists and
is tested · **[design]** specified, not built in this increment.

### State transition (before → integrated)

| Aspect | Before (library-only) | Integrated (now) |
|---|---|---|
| Where the gate runs | a `HandshakeGuard` object exercised by tests | **inside the daemon accept loop**, every connection |
| Cookie binding | a caller-supplied `source` byte string | the **kernel-observed peer IP** (`peer_addr().ip()`), unforgeable by the client |
| Wire protocol | gate not on the wire | a cookie round-trip precedes the ClientHello on the live socket |
| Aggregate limits | per-source only | per-source **+ global PQC-rate + in-flight concurrency** caps |
| Evidence | PQC-invocation counts in-process | in-process counts **plus on-the-wire** outcome classification |

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

Per-source key note: the source is now the **kernel-observed peer IP**, hashed to
`SHA-256(IP)[..16]`. Keying on the IP (not ip:port) is deliberate — an attacker
cannot escape per-source rate limiting or replay detection by opening connections
from fresh ephemeral ports.

### 3.5 Global PQC-work and concurrency limits (requirement 3, aggregate)

Per-source limiting bounds each individual source, but a **distributed** flood
(many distinct, individually-under-budget sources) could still aggregate into
unbounded responder work. Two global controls, consulted *after* `admit` and
*before* `respond()` via `try_acquire_pqc(now)`, close that gap:

- **Global admitted-PQC rate** — a single all-sources token bucket
  (`global_pqc_per_sec`, `global_pqc_burst`). Over budget → `GlobalRateLimited`.
- **In-flight concurrency cap** — at most `max_in_flight_pqc` PQC handshakes
  proceed at once; beyond that → `AtCapacity` (load-shed). An RAII permit
  (`over_socket::PqcPermit`) releases the slot on every exit path, including
  panic. **[implemented]**

A connection shed by either control performs **no PQC**; a legitimate peer simply
reconnects for a fresh cookie. Forged cookies are rejected at the MAC check
*before* the global gate, so an attacker cannot drain the global bucket cheaply.

### 3.6 Live daemon integration (requirement 1 & 2)

`src/bin/daemon.rs` creates one process-wide `Arc<Mutex<HandshakeGuard>>` per
listener and runs **every** accepted connection (both the over-socket TCP mode
and the SCM_RIGHTS fd-passing mode) through `establish_and_bridge_gated`, which:

1. derives the source from the **kernel-reported peer IP** (requirement 2);
2. Phase 0 — `request()` (per-source rate-limit + issue cookie), sends the cookie;
3. Phase 1 — reads `Cookie ‖ ClientHello`, runs `admit()` then `try_acquire_pqc()`;
4. only past both gates runs `respond()` (PQC) and bridges to kTLS.

The lock is held only for the synchronous gate calls, never across an `await` or
across the PQC computation, so the gate does not serialise handshakes.
**[implemented]** — exercised end-to-end by `tests/chaos_orchestration.rs`
(spawns the real daemon binary) and `tests/handshake_dos_integration.rs`.

### 3.7 Failure semantics

Every rejection path returns an `AdmissionError` (`Throttled`, `Expired`,
`BadMac`, `Replay`, `Malformed`, `GlobalRateLimited`, `AtCapacity`) and the caller
drops the connection. No path yields plaintext or partial key material, consistent
with the overlay's fail-closed invariant.

## 4. What is NOT claimed here (honesty boundary)

- The gate is wired into the daemon's **TCP accept** path and its **fd-passing**
  path. The **eBPF RingBuf** event source remains out-of-tree (no `bpf-linker`/
  CAP_BPF here); when that transport is built, the same `establish_and_bridge_gated`
  contract applies — but that path is **[design]** in this sandbox.
- No timing benchmark of the responder under load is claimed — this sandbox is
  not representative hardware, so a wall-clock "requests/sec sustained" figure
  would be fabricated. The evidence is **operation counts** (PQC invocations /
  on-the-wire admit-vs-reject outcomes), which are hardware-independent and
  decisive for the asymmetric-work property.

## 5. Validation evidence

Reproduce:

```
cargo test --lib handshake_guard
cargo test --test handshake_dos_tests --test handshake_dos_integration -- --nocapture
cargo test --test chaos_orchestration         # spawns the real daemon binary
```

### 5.1 Unit tests (`src/handshake_guard.rs`, 16 tests, **[measured]** all pass)

Cookie wire round-trip; forged → `BadMac`; cookie does not transfer across
sources; replay → `Replay`; expired/future → `Expired`; malformed bytes → parse
`None`; per-source burst throttled to capacity; bucket refill; secret rotation
keeps the previous epoch valid; source map bounded under a 10 000-source flood;
**global rate gate caps aggregate admits across sources**; **global rate refills
over time**; **concurrency gate caps in-flight PQC**; release is saturating.

### 5.2 In-process, against the real PQC responder (`tests/handshake_dos_tests.rs`, 7 tests, **[measured]** this run)

| Scenario | Attacker volume | Real PQC `respond()` invocations | Other |
|---|---:|---:|---|
| Legitimate flood, 1 source, rate 20 burst / 10 s⁻¹ | 1 000 attempts | **20** (= burst budget) | 980 throttled |
| Invalid (forged-cookie) flood | 50 000 | **0** | 50 000 rejected |
| Spoofed-source flood (no return-routability) | 20 000 sources | **0** | source map ≤ cap |
| Replayed handshake | 10 000 submissions | **1** | 9 999 `Replay` |
| Malformed messages (6 lengths × 1 000) | 6 000 | **0** | no panic |
| Mixed blended assault + 3 honest sources | 100 000 nuisance | **15** (only honest) | sources ≤ 512, replay ≤ 1024 |
| **Distributed flood, 5 000 distinct sources, global burst 25** | 5 000 sources | **25** (= global burst) | 4 975 globally shed |

### 5.3 On the real wire, through the live gated path (`tests/handshake_dos_integration.rs`, 4 tests, **[measured]** this run)

Each test runs `over_socket::establish_and_bridge_gated` — the function the daemon
calls — over loopback TCP, classifying whether each connection **reached the PQC
stage** or was **rejected at the gate**:

| Scenario | Connections | Reached PQC | Rejected at gate |
|---|---:|---:|---|
| Genuine peers (cookie round-trip + real handshake) | 3 | **3** | 0 |
| Forged-cookie flood on the wire | 10 | **0** | 10 `BadMac` |
| Replayed cookie (captured, reused from a new connection) | 1 + 5 | **1** | 5 `Replay` |
| Concurrent load, global burst = 5, no refill | 40 | **5** | 35 globally shed |

End-to-end against the **spawned daemon binary**: `tests/chaos_orchestration.rs`
completes real gated handshakes while the daemon is alive and fails closed when it
is killed (no hang, no plaintext).

### 5.4 Decisive properties demonstrated

1. **Invalid, spoofed, malformed, and forged-on-the-wire floods drive the PQC
   responder exactly zero times** — the asymmetric-work primitive is removed,
   *on the live path*.
2. **A replayed handshake triggers PQC at most once** — in-process and on the wire.
3. **A legitimate single-source flood is capped at the per-source rate budget.**
4. **A distributed flood is capped at the global burst** regardless of source
   count (25/5 000 in-process; 5/40 on the wire).
5. **Bounded memory** — source and replay structures never exceed configured caps
   under six-figure floods.

## 6. Residual risks

- **R1 — Sustained distributed return-routable flood (botnet).** The global rate +
  concurrency caps now bound *aggregate* responder PQC work (§5.2, §5.3), so the
  responder can no longer be CPU-exhausted. The residual is a **fairness/
  availability** concern: under a large botnet of genuinely reachable sources, the
  global budget is consumed and *legitimate* peers compete for the remaining
  admissions (they retry, but may be delayed). Mitigations (**[design]**):
  priority/allow-listing of known-good peers, and deployment behind the eBPF/cgroup
  ingress controls. Severity reduced from "DoS" to "degraded fairness under flood".
- **R2 — Cookie issuance is itself work.** Phase 0 costs one HMAC + one RNG draw
  per connection. HMAC-SHA256 is ~3–4 orders of magnitude cheaper than the
  ML-DSA-65 signing it replaces, and the source map is capped; for line-rate
  packet floods this constant-cost reflection should still sit behind kernel/eBPF
  ingress rate controls. Standard cookie trade-off.
- **R3 — Clock dependence.** Freshness uses a coarse monotonic clock
  (`monotonic_secs`, derived from a process-start `Instant`, so it cannot run
  backwards). The 2 s future-skew allowance and current+previous secret retention
  bound the impact of rotation boundaries.
- **R4 — Mutex on the shared guard.** All gate calls take a process-wide `Mutex`
  briefly (never across `await` or PQC). At extreme connection rates this lock is
  a potential contention point; it is **not** held during PQC, so it does not
  serialise the expensive work. A sharded/lock-free guard is a future optimisation
  (**[design]**), not a correctness issue.
- **R5 — eBPF event-source transport.** The gate covers the TCP-accept and
  fd-passing paths; the out-of-tree eBPF RingBuf transport will use the same
  `establish_and_bridge_gated` contract when built (**[design]** here).

## 7. Test ↔ requirement traceability

| Requirement | Test(s) |
|---|---|
| 1. Integrate into the real daemon accept path | `chaos_orchestration::daemon_context_kill_fails_closed` (spawns daemon); `handshake_dos_integration::*` (the gated wire path) |
| 2. Bind cookie to live peer identity | `handshake_dos_integration::gated_path_rejects_forged_cookie_before_pqc`, `…rejects_replayed_cookie`; `handshake_guard::cookie_bound_to_source_does_not_transfer` |
| 3a. Per-source rate limiting | `rate_limiter_throttles_a_single_source_burst`, `…refills_over_time`, `legitimate_flood_is_capped_by_rate_budget_not_per_packet` |
| 3b. Global PQC-work + concurrency limits | `global_rate_gate_caps_aggregate_pqc_across_sources`, `global_rate_gate_refills_over_time`, `concurrency_gate_caps_in_flight_pqc`, `distributed_source_flood_is_bounded_by_global_gate`, `handshake_dos_integration::global_gate_caps_admitted_pqc_under_concurrent_load` |
| 4. Replay-resistant challenge | `replayed_cookie_is_rejected`, `replayed_handshake_triggers_pqc_at_most_once`, `handshake_dos_integration::gated_path_rejects_replayed_cookie`, `expired_/future_dated_cookie_is_rejected` |
| 5. Invalid / spoofed / replay / distributed / load | the seven `handshake_dos_tests` + the four `handshake_dos_integration` wire tests |
