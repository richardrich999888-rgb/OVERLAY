# SYNTRIASS Overlay — Measured Benchmarks

All numbers below are **measured**, not asserted. Each row says how to reproduce
it. Where a target depends on a component that does not exist yet (v2 eBPF/kTLS
data plane, the Mission-Adaptive state machine), the row is marked
**NOT IMPLEMENTED** rather than given a fabricated value.

## Test environment

- Host: containerized sandbox, `nproc` = 4 cores, x86-64.
- Network: loopback (`127.0.0.1`) via a userspace recording relay (no NIC, no
  `tc`/netem — those need Docker/CAP_NET_RAW, see `tests/netimpair_test.py`).
- Build: `rustc 1.94.1`, `--release` (`opt-level = 3`, `panic = "unwind"`).
- Caveat: a dedicated bare-metal server (e.g. 3.3 GHz, AVX2) would be faster than
  this shared 4-core sandbox, but not by the multiples needed to flip the MISS
  rows below (handshake latency is ~3x over target; size is ~6.5x over).

## Scorecard

Reproduce the crypto rows with `cargo bench` (harness in `benches/demo_benchmarks.rs`),
the end-to-end rows with `python3 tests/characterize.py`, and the stability row
with `cargo test crash_isolation`.

| Category | Target | Measured | Verdict |
|---|---|---|---|
| Control-plane handshake latency (in-band) | P99 ≤ 1.5 ms | **P50 ~2.0 ms, P99 ~4.4 ms** (in-proc, post identity-cache). End-to-end median **2.3 ms** (was 3.7 ms before the cache fix) | ❌ **MISS ~3x** — bounded by ML-DSA |
| …same handshake, ML-KEM-only projection | P99 ≤ 1.5 ms | **P50 0.33 ms, P99 0.38 ms** (768) — *unauthenticated* | ✅ **PASS** (shows the path to target = out-of-band auth) |
| Handshake wire size (in-band) | ≤ 2 KB | **13.06 KB** (768), **13.93 KB** (1024); ML-KEM-only projection **2.3 KB** (768) | ❌ **MISS** (even KEM-only is 2.3 KB) |
| Data-plane throughput | ≥ 95% line-rate | **12.8–15.5%** of loopback (v1 userspace); AEAD ceiling 546 MB/s (not the bottleneck) | ❌ MISS (v2 kTLS path not wired) |
| eBPF hook invocation | ≤ 45 ns | eBPF program is a non-loading scaffold | ⬜ **NOT IMPLEMENTED** |
| Availability switchover | ≤ 100 µs | **encrypted** degraded fallback (no plaintext): control-plane decision+derive mean **47 µs**, max **164 µs**. eBPF kernel switch not implemented | 🔶 **Partial** (control-plane only) |
| Host process crash rate | 0.00% | release now `panic = "unwind"` + poison-recovery; fault-injection test proves panic → **EIO + host upright** | ✅ **MET** (was SIGABRT under `panic="abort"`) |

## Detail and reproduction

### 1. Handshake latency — `P99 4.2–4.7 ms` vs 1.5 ms target → MISS

In-process crypto only (isolates the asymmetric cost from TCP/Python), n=500 + 30 warmup:

```
NistStandard768  [identity cached]  mean=2.128  p50=1.901  p90=3.162  p99=4.682  max=6.442  (ms)
NistStandard768  [identity rebuilt] mean=3.167  p50=2.948  p90=4.287  p99=5.642  max=7.499  (ms)
NistStandard1024 [identity cached]  mean=2.254  p50=2.109  p90=3.210  p99=4.221  max=5.154  (ms)
NistStandard1024 [identity rebuilt] mean=3.217  p50=3.073  p90=4.148  p99=5.416  max=7.061  (ms)
```

- Even the **median** (~1.9 ms) exceeds the **P99** target of 1.5 ms.
- The cost is **not** ML-KEM (KEM enc/dec is sub-ms). It is the **two ML-DSA-65
  signatures + two verifications per handshake** plus Ed25519. Lattice signatures,
  not KEM, dominate.
- `[identity rebuilt]` vs `[identity cached]` quantified a real fix that is **now
  applied**: `resolve_identity()` no longer rebuilds Ed25519/ML-DSA keys per
  handshake — the constructed `IdentityMaterial` is cached behind an `Arc`. This
  cut end-to-end median from **3.7 ms → 2.3 ms (−38%)** and raised setup rate
  ~+48%. It still does not reach 1.5 ms; ML-DSA sign/verify dominates.
- The `[2]` ML-KEM-only projection (P99 **0.38 ms**) shows the residual is the
  signature, not the KEM: out-of-band identity auth is the only way to ≤1.5 ms.

Reproduce: `cargo bench` (section [1] in-band, [2] ML-KEM-only projection)

End-to-end (TCP + apps, `tests/characterize.py`): post-cache median **2.22–2.39 ms**,
p95 **3.79–3.89 ms** (was median 3.70–3.75 ms, p95 5.17–5.40 ms before the fix).

### 2. Handshake size — `13 KB` vs 2 KB target → MISS

```
NistStandard768   ClientHello=6579 B  ServerHello=6483 B  total=13062 B  (12.8 KB)
NistStandard1024  ClientHello=6963 B  ServerHello=6963 B  total=13926 B  (13.6 KB)
```

Per-hello breakdown (why 2 KB is infeasible with in-band PQ auth):

| Field | Bytes |
|---|---|
| X25519 public | 32 |
| ML-KEM ek/ct (768) | 1184 / 1088 |
| Ed25519 public + sig | 32 + 64 |
| **ML-DSA-65 public** | **1952** |
| **ML-DSA-65 signature** | **3309** |

ML-DSA-65 material alone is **5261 B per hello** — 2.5x the entire 2 KB budget,
before any KEM bytes. Reaching ≤2 KB would require dropping in-band PQ signatures
(pre-distribute identity keys, reference by hash) and even then ML-KEM-1024
ct+pk ≈ 3.1 KB still exceeds 2 KB. **The 2 KB target is incompatible with the
current PQ-mutual-auth design and should be re-baselined to ~13–14 KB.**

Reproduce: `cargo bench` (section [3])

### 3. Data-plane throughput — `12.8–15.5%` vs ≥95% target → MISS (v1)

End-to-end loopback (`characterize.py`): 293–332 MB/s vs 2147–2280 MB/s plain TCP.

This is a **v1 (userspace `LD_PRELOAD`) limitation**, not a cipher limitation. The
AEAD itself is far faster: in-process seal+open measures **547 MB/s** (two GCM ops
per record ⇒ ~1.1 GB/s one-way). The bottleneck is userspace buffer copies across
the syscall boundary — exactly what the v2 kTLS zero-copy path is meant to remove.
The ≥95% target therefore **cannot be evaluated until the v2 kTLS data plane is
wired to the handshake** (the kTLS install primitive now exists and is tested in
`tests/ktls_roundtrip.rs`, but the PQC→kTLS secret bridge does not).

Reproduce: `cargo bench` (section [4]) and `python3 tests/characterize.py`.

### 4 & 5. eBPF hook latency / Kinetic switchover — NOT IMPLEMENTED

`ebpf/src/main.rs` is a conceptual scaffold (no loader, `socket_cookie`/`cgroup_id`
return 0, no RingBuf). `OPERATION_MODE_FLAG`, `handle_handshake_failure`, and the
Garrison/Kinetic state machine do not exist in any ref. These targets cannot be
measured until the components are built, and should not appear as achieved values
in any dossier.

### 6. Host crash rate — FIXED (was inert under `panic = "abort"`)

Originally the release profile used `panic = "abort"`, under which `catch_unwind`
cannot catch — a panic calls `abort()` immediately. Demonstrated directly:

```
# rustc -C panic=unwind : catch_unwind CAUGHT -> process survives (exit 0)
# rustc -C panic=abort  : process Aborted (SIGABRT, exit 134)
```

Fix (committed): the release profile is now `panic = "unwind"`, so the
`ffi_guard_*` shields are load-bearing; registry-lock poisoning is recovered
(`into_inner`) and per-fd poisoning fails just that connection closed with EIO.
A fault-injection test proves it:

```
cargo test crash_isolation
  ffi_guard_converts_panic_to_eio_without_crashing ... ok   # panic -> -1/EIO, host upright
  registry_lock_recovers_from_poison ... ok
  poisoned_fd_state_is_fail_closed_detectable ... ok
```

### 7. Availability under daemon outage — encrypted fallback, never plaintext

The "Kinetic" plaintext bypass was **not** built. Instead `select_posture()`
returns `FullPqc` / `EncryptedFallback` / `FailClosed` — there is no `Plaintext`
variant, so cleartext egress is unrepresentable. When the control plane is down
and a PSK is configured, `derive_fallback_session()` gives a quantum-safe
AES-256-GCM channel (no forward secrecy; documented tradeoff). Measured
control-plane decision+derive latency: mean ~47 µs, max ~164 µs
(`tests/defense_scenario_tests.rs`). This is a control-plane number, **not** the
eBPF kernel switchover (that data plane is still unimplemented).

## What an evaluator should take away

- The **correctness/security** posture is strong and tested (fail-closed, fork
  safety, egress blocking, mutual PQ auth, host-crash isolation, no-plaintext
  fallback).
- **Latency** improved ~38% via identity caching (e2e median 3.7 → 2.3 ms) but
  in-band still misses 1.5 ms by ~3x; the **ML-KEM-only projection meets it
  (P99 0.38 ms)**, so the target is reachable only by moving identity auth
  out-of-band.
- **Size** misses ~6.5x in-band and ~1.15x even KEM-only (2.3 KB); the 2 KB
  target needs re-baselining.
- **Throughput** ≥95% and the **eBPF hook ≤45 ns** remain v2 dependencies (kTLS
  install primitive exists and is tested; eBPF data plane and PQC→kTLS bridge do
  not). These must not be reported as achieved before they are built.
