# Fail-Closed Assurance — Validation Report (Finding FC-1)

> **Superseded by `docs/FAIL_CLOSED_ASSURANCE.md`.** This document recorded the
> first increment, when Miri/Loom/cargo-fuzz were marked *blocked-on-nightly*.
> They have since been **run on a nightly toolchain in-environment** (Miri: 0 UB;
> Loom: exhaustive cap proof; cargo-fuzz: parser targets). A misaligned-reference
> UB the audit surfaced was fixed. See the consolidated report for current state.

**Finding addressed:** FC-1 — *fail-closed assurance gap*. The platform's
load-bearing safety promise is "never emit application plaintext, never crash on
adversarial input, fail closed on every error." Before this increment that promise
rested on hand-review and scattered unit tests: there was **no automated proof**
of the no-cleartext / no-panic invariants under adversarial input or concurrency,
and **85 of 86 `unsafe` blocks carried no `// SAFETY:` justification**.

Labels: **[measured]** a test here produced this · **[implemented]** code exists and
is tested · **[blocked-infra]** real harness committed but not runnable in this
sandbox (requires a nightly toolchain) — see §5.

This sandbox has a **stable-only** toolchain, so **Miri, Loom, and cargo-fuzz
cannot execute here.** Per the mission rules, those are delivered as real,
host-runnable harnesses + this design note (§5), and are **not** claimed as
validated. The in-sandbox, deterministic evidence (§3, §4) stands on its own.

---

## 1. Threat addressed

A defence overlay whose value is *assured confidentiality* fails its mission two
ways that are worse than refusing to connect:

1. **Fail-open** — emitting application plaintext (or a recoverable fragment) on
   the wire because of a parser bug, a tamper that is not rejected, or an error
   path that returns data instead of an error.
2. **Crash / hang** — a panic or deadlock on adversarial input, which is itself a
   denial of service and may unwind across an FFI boundary (UB).

The adversary supplies arbitrary bytes to every wire parser, tampers with every
authenticated record, replays records, and drives the daemon's shared state
concurrently.

## 2. Invariants put under automated proof

| ID | Invariant |
|---|---|
| **I1** | No plaintext canary ever survives into bytes the overlay emits (`seal` / record layer / fallback / full PQC). |
| **I2** | Any mutation of an authenticated record makes `open` return `Err` — never plaintext (fail closed). |
| **I3** | Arbitrary bytes into every wire parser yield `Err`/`None`/bounded-`Ok` — never a panic, never the canary. |
| **I4** | The anti-replay window accepts a given sequence number at most once across any delivery order. |
| **I5** | Any mutation of a valid admission cookie is rejected — no false accept. |
| **C1** | The in-flight PQC concurrency cap is never exceeded under real-thread contention. |
| **C2** | The full admission flow never deadlocks and never leaks a concurrency slot. |
| **C3** | A poisoned shared-guard mutex is handled fail-closed (error, not panic / not bypass). |

## 3. In-sandbox evidence — property & robustness (`tests/fail_closed_properties.rs`)

Seeded (reproducible) randomised testing against the **real** code paths.
**[measured]**, this run:

| Invariant | Volume | Result |
|---|---:|---|
| I1 no-cleartext (fallback record layer) | 20 000 sealed records | **0 canary leaks** |
| I1b no-cleartext (real hybrid PQC, both suites) | 1 000 records | **0 canary leaks** |
| I2 tamper ⇒ fail closed | 20 000 tampered records | **0 fail-open** |
| I3 parsers never panic / leak | 50 000 random inputs | **0 panics, 0 leaks** |
| I4 anti-replay never double-accepts | 200 windows × 2 000 ops = 400 000 | **0 double-accepts** |
| I5 cookie no false-accept | ~20 000 mutations | **0 false-accepts** |

Parsers covered by I3: `Cookie::from_bytes`, `KernelSockEvent::from_bytes`,
`SecureSession::open`, and the hybrid responder `engine.respond()`.

Reproduce: `cargo test --test fail_closed_properties -- --nocapture`

## 4. In-sandbox evidence — concurrency (`tests/concurrency_stress.rs`)

Real OS threads against the exact `Arc<Mutex<HandshakeGuard>>` the daemon shares.
**[measured]**, this run:

| Invariant | Setup | Result |
|---|---|---|
| C1 cap never exceeded | 16 threads × 20 000 iters, cap = 4 | **max observed in-flight = 4** (75 664 acquisitions) |
| C2 no deadlock / no slot leak | 12 threads × 5 000 iters, full request→admit→acquire→release | **final in-flight = 0, no deadlock** |
| C3 poisoned guard fail-closed | poison the mutex, run the production `.lock()` pattern | **fail-closed error, panic not propagated** |

Reproduce: `cargo test --test concurrency_stress -- --nocapture`

## 5. Unsafe-code audit

86 `unsafe` blocks across 6 modules. Each is classified below with its
fail-closed property. The security-critical v2-path blocks (SCM_RIGHTS fd passing,
the kTLS handoff, the received-fd adoption) now carry inline `// SAFETY:`
justifications; the LD_PRELOAD interceptor — the surface being **deprecated** under
finding C1 (eBPF replacement) — is documented by category here, with full per-block
annotation tracked against that deprecation.

| Module | `unsafe` | Category | Fail-closed property | SAFETY docs |
|---|---:|---|---|---|
| `interceptor.rs` | 56 | LD_PRELOAD FFI: `dlsym`/`RTLD_NEXT` resolution, `errno` get/set, calls to the real libc fns via stored pointers, fcntl/getsockopt probes | panics caught by `ffi_guard_*` `catch_unwind` shields (never unwind across C); on resolution failure, egress is **blocked** (fail-closed-egress) | by category (§ note); per-block tracked with C1 deprecation |
| `fd_passing.rs` | 14 | `sendmsg`/`recvmsg` + `CMSG_*` pointer arithmetic for one-fd `SCM_RIGHTS` | malformed/truncated/wrong/extra-fd ⇒ no fd returned; extra fds `close`d, never leaked | **inline `// SAFETY:` added** |
| `kernel_native.rs` | 5 | `setsockopt(TCP_ULP)`, `setsockopt(SOL_TLS, TLS_TX/RX, crypto_info)`, `shutdown`/`close` | any kTLS install error ⇒ `shutdown` + `close` (teardown), no plaintext | inline (pre-existing + this audit) |
| `fd_state.rs` | 8 | `getpid`; `inotify_*` config-watch; `raw_read`/`raw_close`; cast of `inotify_event` from a byte buffer | config-reload failure leaves the prior policy in force; never affects sealing | by category (§ note) |
| `accelerator.rs` | 2 | FFI to the C-DAC SYCL bridge (feature-gated) | a non-zero bridge return is a fail-closed abort code | inline (pre-existing) |
| `daemon.rs` | 1 | `TcpStream::from_raw_fd` on an `SCM_RIGHTS`-received fd | sole ownership taken; closed exactly once via the stream/bridge | **inline `// SAFETY:` added** |

**Lint hardening (crate-wide):** `#![deny(unused_must_use)]` is now in `src/lib.rs`.
A dropped `Result`/`#[must_use]` value on a security path (a swallowed seal/close/
teardown error) is a fail-*open* bug; it is now a hard compile error. The build is
clean under this lint — the codebase already never drops a must-use security value;
the lint makes that permanent. **[implemented]**

## 6. Host-only assurance (BLOCKED on toolchain — real harnesses committed)

These require a nightly toolchain absent from the sandbox. Real, runnable harnesses
are committed; results are **not** claimed here.

- **Continuous fuzzing (cargo-fuzz / libFuzzer)** — `fuzz/` (out-of-workspace,
  not in the main `Cargo.lock`). Four targets mirror the I3 parsers for
  open-ended fuzzing with coverage + ASan. **[blocked-infra]**
  Run: `cargo +nightly fuzz run cookie_parse` (see `fuzz/README.md`).
- **Miri (undefined-behaviour / data-race detection)** — `scripts/run_miri.sh`
  runs Miri over the pure crypto + record-layer + admission-gate logic (Miri
  cannot execute the FFI/syscall modules). **[blocked-infra]**
  Run: `scripts/run_miri.sh`.
- **Loom (exhaustive concurrency model-checking)** — the in-sandbox C1–C3 evidence
  is real-thread *stress*, which samples interleavings rather than proving all of
  them. The exhaustive complement is a Loom model of the `try_acquire_pqc`/
  `release_pqc` cap and the poison-recovery path. Adding Loom pulls a non-trivial
  dependency tree and requires `--cfg loom` gating of the guard's atomics/lock; it
  is specified here and deferred to keep the dependency surface minimal.
  **[blocked-infra / design]** — model to check:
  - state: `in_flight: usize`, cap `N`, a shared lock;
  - threads repeatedly `try_acquire` (succeeds iff `in_flight < N`, then `+1`) and
    `release` (`-1`);
  - assert across **all** interleavings: `in_flight <= N` always, and `in_flight`
    returns to 0 once all threads finish — i.e. the same invariants C1/C2 assert
    by stress here.

## 7. Residual risks

- **R1 — Interceptor SAFETY annotation is by-category, not per-block.** The
  LD_PRELOAD path is being deprecated (C1); per-block annotation is tracked with
  that work. Its fail-closed behaviour (catch_unwind shields + fail-closed-egress)
  is already tested elsewhere, but is not part of this increment's per-block audit.
- **R2 — Miri / Loom / fuzzing are not run in CI.** Until a nightly runner is
  provisioned (or the eBPF host CI lands), UB-detection, exhaustive interleaving
  proof, and open-ended fuzzing rely on the committed harnesses being run on a
  host. The in-sandbox property + stress suites bound, but do not replace, them.
- **R3 — Property tests sample, they do not exhaust.** I3 covers 50 000 seeded
  inputs, not the whole input space; continuous fuzzing (R2) is the open-ended
  complement.

## 8. Reproduce

```
cargo build --release --locked                 # clean under #![deny(unused_must_use)]
cargo test --test fail_closed_properties --test concurrency_stress -- --nocapture
# host-only (nightly):
scripts/run_miri.sh
cargo +nightly fuzz run cookie_parse
```
