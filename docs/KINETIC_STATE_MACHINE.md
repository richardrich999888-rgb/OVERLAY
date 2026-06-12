# Kinetic State Machine (Phase 4)

Tags: **[measured]** real run · **[tested]** automated assertion · **[implemented]**
code exists · **[design]** needs external infra.

**Objective:** autonomous operational recovery — the platform moves itself between
operational postures as the environment degrades and recovers, with **no plaintext
state** ever introduced.

## 1. The three postures (and only these three)

| Mode | `OPERATION_MODE_FLAG` | Meaning | Egress |
|---|:--:|---|---|
| `FullPqc` | 0 | hybrid-PQC control plane healthy | allow |
| `EncryptedFallback` | 1 | PQC unavailable; encrypted PSK path (AES-256, **never plaintext**) | allow |
| `FailClosed` | 2 | no safe channel | **deny** |

The `OperationMode` type has **no `Plaintext` variant** — a plaintext posture is
*unrepresentable*, enforced by the compiler (`no_plaintext_mode_exists` proves the
exhaustive match). The `flag()` value is exactly the eBPF `operation_mode` map
value the Phase-3 policy engine enforces (`docs/EBPF_POLICY_ENGINE.md`).

## 2. Implementation — **[implemented]** (`src/kinetic.rs`)

- **`Supervisor`** — the supervisor loop: consumes `HealthEvent`s
  (`HandshakeSuccess`/`HandshakeFailure`/`SecurityViolation`) and transitions
  autonomously per `KineticConfig` thresholds.
- **`handle_handshake_failure` / `handle_handshake_success`** — the named entry
  points; degrade on sustained failure, recover on sustained success.
- **`force_fail_closed`** — a *security* fail-closed that is **sticky**: only a
  manual `reset()` clears it (autonomous recovery must not reopen a channel a
  security event closed). A *degraded* (link-down) fail-closed **is** autonomously
  recoverable.
- **`operation_mode_flag()`** — the `OPERATION_MODE_FLAG` the daemon pushes into
  the kernel `operation_mode` map on every change (Phase-3 integration).

### Transition edges

```
                 sustained failures (>=3)            sustained failures (>=3)
   FullPqc ───────────────────────────► EncryptedFallback ──────────────────► FailClosed
      ▲   ◄───────────────────────────                     ◄── (degraded only) ──┘
      │      sustained successes (>=2)        sustained successes (>=2)
      └──────────────────────────────────────────────────────────────────────────
   (no fallback provisioned: FullPqc degrades straight to FailClosed — NEVER plaintext)
   SecurityViolation ⇒ FailClosed (sticky; manual reset only)
```

## 3. Validation — **[measured]** + **[tested]**

`cargo test --release --test kinetic_failover_tests -- --nocapture` (failover/
recovery driven by **real** handshakes: an untrusted client → `respond()` Err =
failure; a trusted client = success):

| metric | value |
|---|---:|
| failover FullPqc → EncryptedFallback | **2 035 µs** (3 real failing handshakes) |
| failover FullPqc → FailClosed (total) | **3 695 µs** (6 real failing handshakes) |
| recovery → FullPqc (sustained successes) | **8 074 µs** |
| state-machine per-event processing | **2.2 ns** |
| posture transitions in the run | 4 (ended `FullPqc`) |

`cargo test --lib kinetic` (7 unit tests, all pass):

| Property | Test |
|---|---|
| Starts FullPqc (flag 0) | `starts_full_pqc` |
| Degrade FullPqc → EncryptedFallback → FailClosed | `degrades_to_fallback_then_fail_closed` |
| **No fallback ⇒ straight to FailClosed, never plaintext** | `no_fallback_degrades_straight_to_fail_closed_never_plaintext` |
| Recover from EncryptedFallback on sustained success | `recovers_from_fallback_on_sustained_success` |
| Degraded fail-closed recovers; **security lock is sticky** | `degraded_fail_closed_recovers_but_security_lock_is_sticky` |
| **No plaintext mode exists** (exhaustive match) | `no_plaintext_mode_exists` |
| Random event sequences never reach a forbidden state (2000×200) | `random_event_sequences_never_reach_a_forbidden_state` |
| Security fail-closed sticky through 20 **real** successes | `security_violation_is_sticky_under_real_successes` |

## 4. Success criteria — status

| Criterion | Status |
|---|---|
| Automatic posture transitions occur | ✅ [measured] (4 transitions; failover 2.0/3.7 ms, recovery 8.1 ms) |
| No plaintext state introduced | ✅ [tested] (`OperationMode` has no `Plaintext` variant; exhaustive-match proof; fuzz over 400 000 events) |
| Recovery behaviour documented | ✅ this doc §2–§3 + `docs/RECOVERY_ANALYSIS.md` |

## 5. Integration & residual

- The supervisor is the **userspace half** of the autonomous control plane; on
  each transition it writes `operation_mode_flag()` into the eBPF `operation_mode`
  map (Phase 3), so the kernel enforces the new posture (measured separately:
  posture push 1–3 µs, FailClosed→EPERM).
- **Residual [design]**: wiring the `Supervisor` into the live daemon's handshake
  loop (feeding it real per-connection outcomes and pushing the flag to the map on
  the BPF host) is the remaining plumbing; the state-machine logic + transition
  correctness + failover/recovery timing are measured here.
- Thresholds (`KineticConfig`) are deployment policy; the defaults (3/3/2) give the
  measured ~2 ms failover; tune per link characteristics.
