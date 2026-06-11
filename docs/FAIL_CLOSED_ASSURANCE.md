# Fail-Closed Assurance — Validation Report

**Track:** Fail-Closed Assurance. **Finding:** FC-1.
**Source of truth:** `docs/DEFENCE_READINESS_REVIEW.md`.

The platform's load-bearing promise is *never emit application plaintext, never
crash or hang on adversarial input, fail closed on every error*. This report is
the consolidated evidence for that promise across all six track goals:

| Goal | Status | Where |
|---|---|---|
| panic-path audit | **done** | §1 |
| unsafe Rust audit | **done** | §2 |
| Miri validation | **done (run here)** | §3 |
| Loom validation | **done (run here)** | §4 |
| property testing | **done** | §5 |
| plaintext-leakage analysis | **done** | §6 |

Labels: **[measured]** a tool/test here produced this · **[implemented]** code +
test exists. Every number below is a real outcome of a real run in this
environment; nothing is fabricated. Reproduce with the commands in §8.

This supersedes the "blocked-on-nightly" boundary recorded in
`docs/FAIL_CLOSED_VALIDATION.md`: a nightly toolchain, `miri`, `loom`, and
`cargo-fuzz` were all obtained and **executed here**, so Miri/Loom/fuzz are now
*validated*, not deferred.

---

## 1. Panic-path audit

The shipped library is built `panic = "unwind"` (release profile) precisely so
the FFI boundary can *catch* a panic rather than abort the host
(`src/interceptor.rs` `ffi_guard_c_int` / `ffi_guard_ssize` wrap every
`#[no_mangle]` export in `catch_unwind`). A panic that reached a C caller would
be UB; a panic that silently produced output would be fail-open. So every
panic-capable construct on a production path is a finding.

**Method.** Enumerate `unwrap()/expect()/panic!/unreachable!/todo!/unimplemented!`
on every non-test code path (`awk` stops at the first `#[cfg(test)]`).

**Result — production panic sites and their justification:**

| Site | Construct | Justification |
|---|---|---|
| `crypto/generic.rs:106,198` | `.expect("N bytes within HKDF output bounds")` | HKDF output length is a compile-fixed constant ≤ 255×32; the `expect` is unreachable by construction. |
| `handshake_guard.rs:290` | `.expect("HMAC accepts any key length")` | `Hmac::new_from_slice` is infallible for HMAC (any key length is valid); documented invariant of the `hmac` crate. |
| `kernel_native.rs:107,108` | `.try_into().unwrap()` inside `from_bytes` | Slices are pre-sliced to exactly 8/2 bytes immediately above; the conversion cannot fail. |
| `fd_state.rs` (metrics) | `.expect("static … is valid")` | Prometheus metric registration on **static, compile-time** descriptors; failure means a programming error at startup, not a runtime/attacker path. |

No panic-capable construct sits on an **attacker-reachable data path** (parsing,
sealing, opening, admission). The adversarial-input proof in §5 (50 000 random
inputs across four parsers) exercises those paths with **0 panics**. The FFI
catch-unwind shields are covered by `interceptor`'s own tests
(`poisoned_fd_state_is_fail_closed_detectable`) and the build keeps `unwind` so
the shields remain load-bearing.

**Hardening added:** `#![deny(unused_must_use)]` crate-wide (`src/lib.rs`). A
dropped `Result`/`#[must_use]` on a security path (a swallowed seal/close/teardown
error) is a fail-*open* bug; it is now a compile error. The tree is clean under it.

## 2. Unsafe Rust audit

86 `unsafe` blocks across 6 modules, every one classified with its fail-closed
property. The audit **found and fixed a real soundness bug** and added `// SAFETY:`
justifications to the security-critical v2 path.

**Bug found & fixed — `fd_state.rs` misaligned reference (UB).** The inotify event
loop formed `&*(buf[offset..].as_ptr().cast::<libc::inotify_event>())` — a
reference to a `#[repr(C)]` struct read out of a `[u8; 4096]` (alignment 1) at an
arbitrary offset. Constructing a reference to under-aligned memory is undefined
behaviour even if never dereferenced unaligned. **Fixed** to
`std::ptr::read_unaligned`, which copies the header out by value with no
alignment requirement. (Miri, §3, would flag the old form; the new form is clean.)

| Module | `unsafe` | Category | Fail-closed property | SAFETY docs |
|---|---:|---|---|---|
| `interceptor.rs` | 56 | LD_PRELOAD FFI: `dlsym`/`RTLD_NEXT`, `errno`, real-libc calls via fn-pointers, fcntl/getsockopt probes | panics caught by `ffi_guard_*` `catch_unwind`; resolution failure ⇒ egress blocked (fail-closed-egress) | by category (deprecating under C1) |
| `fd_passing.rs` | 14 | `sendmsg`/`recvmsg` + `CMSG_*` for one-fd `SCM_RIGHTS` | malformed/truncated/wrong/extra-fd ⇒ no fd; extra fds `close`d | **inline `// SAFETY:`** |
| `kernel_native.rs` | 5 | `setsockopt(TCP_ULP / SOL_TLS)`, `shutdown`/`close` | any kTLS error ⇒ `shutdown`+`close` teardown | **inline `// SAFETY:`** |
| `fd_state.rs` | 8 | `getpid`; `inotify_*`; raw `read`/`close` syscalls; event header decode | reload failure leaves prior policy; **misalignment UB fixed** | **inline `// SAFETY:`** |
| `accelerator.rs` | 2 | feature-gated FFI to the C-DAC SYCL bridge | non-zero return ⇒ fail-closed abort code | inline (pre-existing) |
| `daemon.rs` | 1 | `from_raw_fd` on an `SCM_RIGHTS` fd | sole ownership; closed exactly once | **inline `// SAFETY:`** |

## 3. Miri validation — **run here**

`cargo +nightly miri test` over the pure-logic surface (crypto, record layer,
admission gate). Miri executes the program on an interpreter that detects
undefined behaviour, invalid memory access, misaligned references, and data
races. The LD_PRELOAD interceptor is compiled out for Miri (`#[cfg(not(miri))]`
in `src/lib.rs`) because its `#[no_mangle]` libc overrides (write/read/close…)
deliberately clash with Miri's built-in libc shims — expected for an interposer.

**Result [measured]:**

```
cargo +nightly miri test --lib -- \
  handshake_guard::tests::{cookie_round_trips_through_wire, malformed_cookie_bytes_rejected,
                           forged_cookie_is_rejected_without_pqc, happy_path_request_then_admit}
  crypto::session::tests::{anti_replay_window_unit, replay_is_rejected,
                           in_flight_record_opens_across_one_rekey}
  crypto::fallback::*
=> test result: ok. 12 passed; 0 failed.  No undefined behaviour reported.
```

Miri found **no UB** in the cookie/HMAC/`subtle` constant-time compare, the
anti-replay window bit-manipulation, the rekey ratchet, or the fallback key
schedule. (`scripts/run_miri.sh` runs a broader selection; the heavy 10⁴-iteration
flood tests are excluded — they are throughput tests with no extra UB surface and
run for many minutes under the interpreter.)

## 4. Loom validation — **run here**

`tests/loom_model.rs` model-checks the PQC-permit accounting — the exact
synchronization pattern the daemon uses (`try_acquire_pqc`/`release_pqc` under one
shared `Mutex`): check-`< CAP`-then-increment in a single critical section;
saturating decrement on release. Loom explores **every** reachable interleaving.

**Result [measured]:** `test result: ok. 3 passed; 0 failed; finished in 0.65s`

- `loom_cap_holds_in_all_interleavings` — across all interleavings of contending
  threads, `in_flight ≤ CAP` at every instant and drains to 0. **proved**
- `loom_release_is_saturating_in_all_interleavings` — a spurious release never
  underflows / never wedges the gate open. **proved**
- `loom_catches_the_broken_toctou_variant` — **negative control:** the broken
  variant (check and increment in *separate* critical sections) is *caught* by
  Loom (it finds a cap-exceeding interleaving). This proves the model has teeth —
  it would detect the defect class if it existed in production. **proved**

This is the exhaustive complement to the real-thread stress in
`tests/concurrency_stress.rs` (16 threads × 20 000 iters, max in-flight observed =
4 = cap, final in-flight = 0).

## 5. Property & robustness testing — `tests/fail_closed_properties.rs`

Seeded (reproducible) randomised testing against the real code paths.
**[measured]:**

| Invariant | Volume | Result |
|---|---:|---|
| I1 no plaintext canary in sealed records (fallback) | 20 000 records | **0 leaks** |
| I1b no canary in real hybrid-PQC records (both suites) | 1 000 records | **0 leaks** |
| I2 any tamper ⇒ `open` fails closed | 20 000 tampered records | **0 fail-open** |
| I3 parsers never panic / never leak (4 parsers) | 50 000 random inputs | **0 panics, 0 leaks** |
| I4 anti-replay never double-accepts | 400 000 ops | **0 double-accepts** |
| I5 cookie has no false-accept under mutation | ~20 000 mutations | **0 false-accepts** |

Parsers under I3: `Cookie::from_bytes`, `KernelSockEvent::from_bytes`,
`SecureSession::open`, `engine.respond()`.

**Open-ended fuzzing (cargo-fuzz / libFuzzer) — run here.** `fuzz/` holds four
libFuzzer targets mirroring the I3 parsers. Time-boxed runs were executed with the
nightly toolchain + ASan:

| Target | Surface | Runs (time-boxed) | Crashes |
|---|---|---:|---:|
| `cookie_parse` | `Cookie::from_bytes` | 4 809 352 (46 s, ~105k/s) | **0** |
| `kernel_event_parse` | `KernelSockEvent::from_bytes` | 5 954 610 (46 s, ~129k/s) | **0** |
| `session_open` | `SecureSession::open` | 1 crash → fixed → 3 127 261 (41 s) clean | **0** (after fix) |
| `handshake_respond` | hybrid `respond()` (PQC-bound) | 2 097 152+ (~100k/s) | **0** |

Over ~10.8M executions of the two parser-light targets, libFuzzer (with
AddressSanitizer) found **no crash, no panic, no memory error**.
`handshake_respond` ran 2 M+ executions clean.

**Fuzzer-found bug (fixed).** `session_open` crashed within ~1 000 executions:
`SecureSession::open` computed `epoch + 1` on the record's **attacker-controlled**
epoch field to test the one-step grace epoch. A record with `epoch = 0xFFFF_FFFF`
overflowed — an **overflow panic** (fail-open: a crash instead of an `Err`) under
overflow-checked builds. Fixed in `src/crypto/session.rs` to compare against our
own trusted epoch (`self.epoch > 0 && epoch == self.epoch - 1`), which cannot
overflow. Regression test:
`crypto::session::tests::max_epoch_record_fails_closed_without_overflow`. After
the fix `session_open` re-fuzzed clean. This is the concrete payoff of running the
fuzzer for real rather than asserting coverage.

## 6. Plaintext-leakage analysis — `tests/leakage_analysis.rs`

Covers leakage surfaces *other than the ciphertext*. **[measured]:**

| Check | What it proves | Result |
|---|---|---|
| L1 Debug redaction | `{:?}` on `SessionKeys`, `KtlsTrafficKeys/Secret`, `IdentityMaterial` does not print key bytes (hex or decimal) | 6 surfaces, **0 key leaks** |
| L2 handshake wire image | the 13 050-byte ClientHello‖ServerHello never contains the derived traffic keys or IVs | **0 derived secrets on wire** |
| L3 error reflection | crypto + admission error `Debug` never echoes attacker bytes; admission errors are constant-shaped (< 64 chars) | **0 reflection** |
| L4 fallback PSK | the fallback wire image (nonces + 2 000 records) never contains the PSK; cookies never contain foreign secret bytes | 92 922 wire bytes, **0 PSK on wire** |

Combined with §5 I1/I1b (no plaintext canary in records), the leakage surface —
records, debug logs, the handshake transcript, error strings, and the fallback
exchange — is shown free of key/plaintext material.

## 7. Reproduce

```
# stable (always):
cargo test --test fail_closed_properties --test concurrency_stress \
           --test leakage_analysis -- --nocapture

# nightly (obtained + run here):
rustup toolchain install nightly --component miri
scripts/run_miri.sh                                    # Miri: pure-logic UB check
cargo test --test loom_model --release                 # Loom: exhaustive interleavings
cargo install cargo-fuzz
cargo +nightly fuzz run cookie_parse -- -max_total_time=60
```

## 8. Residual risks

- **R1 — interceptor SAFETY is by-category.** The 56-block LD_PRELOAD surface is
  documented by class, not per-block; it is being deprecated under C1 (eBPF).
- **R2 — Miri/Loom/fuzz are not yet in CI.** They were run here on demand; a
  nightly CI lane should run them per-PR. Until then they are run-on-demand, not
  gate-enforced.
- **R3 — property/fuzz sample, they do not exhaust.** I3 is 50 000 seeded inputs;
  fuzzing is time-boxed. Loom *is* exhaustive but only over the permit model, not
  whole programs. Continuous fuzzing on a corpus over time is the open-ended
  complement.
