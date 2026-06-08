# SYNTRIASS Overlay — Measured Benchmarks

All numbers below are **measured**, not asserted. Each row says how to reproduce
it. Where a target depends on a component that does not exist yet (v2 eBPF/kTLS
data plane, the Mission-Adaptive state machine), the row is marked
**NOT IMPLEMENTED** rather than given a fabricated value.

## Test environment

- Host: containerized sandbox, `nproc` = 4 cores, x86-64.
- Network: loopback (`127.0.0.1`) via a userspace recording relay (no NIC, no
  `tc`/netem — those need Docker/CAP_NET_RAW, see `tests/netimpair_test.py`).
- Build: `rustc 1.94.1`, `--release` (`opt-level = 3`, `panic = "abort"`).
- Caveat: a dedicated bare-metal server (e.g. 3.3 GHz, AVX2) would be faster than
  this shared 4-core sandbox, but not by the multiples needed to flip the MISS
  rows below (handshake latency is ~3x over target; size is ~6.5x over).

## Scorecard

| Category | Target | Measured | Verdict |
|---|---|---|---|
| Control-plane handshake latency | P99 ≤ 1.5 ms | **P99 4.2–4.7 ms** (in-proc, identity cached); 5.4–5.6 ms (rebuilt). End-to-end median 3.7 ms, p95 5.2–5.4 ms | ❌ **MISS ~3x** |
| Handshake wire size | ≤ 2 KB | **13.06 KB** (NIST-768), **13.93 KB** (NIST-1024) | ❌ **MISS ~6.5x** |
| Data-plane throughput | ≥ 95% line-rate | **12.8–15.5%** of loopback (v1 userspace) | ❌ MISS (v2 path not wired) |
| eBPF hook invocation | ≤ 45 ns | eBPF program is a non-loading scaffold | ⬜ **NOT IMPLEMENTED** |
| Kinetic switchover | ≤ 100 µs | state machine not in code | ⬜ **NOT IMPLEMENTED** |
| Host process crash rate | 0.00% | `catch_unwind` is **inert under `panic = "abort"`** (release): panic → SIGABRT | ⚠️ **NOT MET in release artifact** |

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
- `[identity rebuilt]` vs `[identity cached]` quantifies a real fix:
  `resolve_identity()` currently rebuilds Ed25519/ML-DSA keys on every handshake.
  Caching saves ~1 ms of mean — worth doing, but does not reach 1.5 ms.

Reproduce: `cargo test --release --lib crypto::bench::bench_handshake_latency -- --nocapture --test-threads=1`

End-to-end (TCP + apps, `tests/characterize.py`): median 3.70–3.75 ms, p95 5.17–5.40 ms.

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

Reproduce: `cargo test --release --lib crypto::bench::bench_handshake_size -- --nocapture --test-threads=1`

### 3. Data-plane throughput — `12.8–15.5%` vs ≥95% target → MISS (v1)

End-to-end loopback (`characterize.py`): 293–332 MB/s vs 2147–2280 MB/s plain TCP.

This is a **v1 (userspace `LD_PRELOAD`) limitation**, not a cipher limitation. The
AEAD itself is far faster: in-process seal+open measures **547 MB/s** (two GCM ops
per record ⇒ ~1.1 GB/s one-way). The bottleneck is userspace buffer copies across
the syscall boundary — exactly what the v2 kTLS zero-copy path is meant to remove.
The ≥95% target therefore **cannot be evaluated until the v2 kTLS data plane is
wired to the handshake** (the kTLS install primitive now exists and is tested in
`tests/ktls_roundtrip.rs`, but the PQC→kTLS secret bridge does not).

Reproduce: `cargo test --release --lib crypto::bench::bench_aead_throughput -- --nocapture --test-threads=1`
and `python3 tests/characterize.py`.

### 4 & 5. eBPF hook latency / Kinetic switchover — NOT IMPLEMENTED

`ebpf/src/main.rs` is a conceptual scaffold (no loader, `socket_cookie`/`cgroup_id`
return 0, no RingBuf). `OPERATION_MODE_FLAG`, `handle_handshake_failure`, and the
Garrison/Kinetic state machine do not exist in any ref. These targets cannot be
measured until the components are built, and should not appear as achieved values
in any dossier.

### 6. Host crash rate — `catch_unwind` inert under release `panic = "abort"`

The release profile sets `panic = "abort"` (correct: unwinding across the C FFI
boundary is UB). But under `panic = "abort"`, `catch_unwind` does **not** catch —
a panic calls `abort()` immediately. Demonstrated directly:

```
# rustc -C panic=unwind : catch_unwind CAUGHT -> process survives (exit 0)
# rustc -C panic=abort  : process Aborted (SIGABRT, exit 134)
```

So the `ffi_guard_*` shields in `src/interceptor.rs` protect debug/test builds but
**are inert in the shipped `.so`**. Compounding this, hot paths use
`REGISTRY.lock().unwrap()`, which aborts on mutex poisoning. To honestly claim
0.00% host-crash either:

1. Keep `panic = "abort"` and **prove panic-freedom** on the interposed path
   (remove `.unwrap()`/poison-abort, audit every reachable panic), or
2. Switch the cdylib to `panic = "unwind"` with an FFI catch shim so the guards
   are load-bearing, then add a fault-injection test asserting the host survives.

Until one of those lands, the 0.00% target is **not met by the release artifact**.

## What an evaluator should take away

- The **correctness/security** posture is strong and tested (fail-closed, fork
  safety, egress blocking, mutual PQ auth).
- The **performance/size targets** as written are not met today: handshake latency
  ~3x over, handshake size ~6.5x over, throughput a v2 dependency.
- Two targets describe **unbuilt v2 components**; one (0.00% crash) is **undermined
  by a build setting**. These are fixable or re-baselineable — but must not be
  reported as achieved before they are.
