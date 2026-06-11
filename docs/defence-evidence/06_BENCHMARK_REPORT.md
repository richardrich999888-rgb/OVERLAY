# 6. Benchmark Report

Tags per `00_INDEX.md`. **Every number here is `[measured]` in this environment**
unless noted. **Host caveat (important for reviewers):** this is a shared,
CPU-only sandbox/host, **not** representative target hardware. Absolute latencies/
throughput will differ on fielded systems; the numbers are reported honestly,
including where they **miss** an aspirational target. Operation *counts* (eBPF
coverage, PQC-invocations, fuzz executions) are hardware-independent and decisive.

## 6.1 Hybrid PQC handshake latency [measured]

`cargo bench --bench demo_benchmarks`, n=300, identity cached:

| Suite | P50 | P99 | Max |
|---|---:|---:|---:|
| NistStandard768 (X25519+ML-KEM-768) | 2.706 ms | 5.650 ms | 6.952 ms |
| NistStandard1024 (X25519+ML-KEM-1024) | 2.864 ms | 6.010 ms | 7.357 ms |
| 768 KEM-only (unauthenticated projection) | 0.401 ms | 0.446 ms | 0.470 ms |
| 1024 KEM-only (unauthenticated projection) | 0.536 ms | 0.586 ms | 0.844 ms |

Honest note: the full (authenticated) handshake **misses** the aspirational
P99 ≤ 1.5 ms target on this host (the cost is dominated by ML-DSA-65 sign+verify).
The KEM-only figures are an *unauthenticated* projection and are **not** a
shippable mode — reported only to localise the cost.

## 6.2 Handshake wire size [measured]

| Quantity | Size | Source |
|---|---:|---|
| Full ClientHello ‖ ServerHello (suite 768, authenticated) | 13 050 B | `leakage_analysis::l2_*` |
| KEM-only envelope (768, unauthenticated projection) | 2 348 B | demo bench |
| KEM-only envelope (1024, unauthenticated projection) | 3 212 B | demo bench |

## 6.3 Symmetric throughput [measured]

| Path | Throughput |
|---|---:|
| Plaintext loopback TCP (v1 line-rate baseline) | 1 535 MB/s (256 MiB) |
| AES-256-GCM seal+open (cipher ceiling) | 488 MB/s (128 MiB) |

The AEAD is not the bottleneck; kTLS moves record encryption into the kernel
(`[implemented]`; in-kernel round-trip `[design]` — kTLS unavailable in this
sandbox).

## 6.4 Universal interception coverage [measured]

`scripts/ebpf_coverage_validate.sh` on kernel 6.18.5, one `cgroup/connect4`
program (`ebpf/COVERAGE_REPORT.txt`):

| Metric | Value |
|---|---|
| Runtimes intercepted | **7 / 7** (glibc, static-glibc, Go, Rust, rust-musl, direct-syscall, python) |
| LD_PRELOAD blind spots caught | **4 / 4** (static, Go, musl-static, raw syscall) |
| Enforcement | connect to a port with a **live listener** → **EPERM deny** (fail-closed) |

## 6.5 Anti-DoS effectiveness (operation counts) [measured]

Real `respond()` (ML-KEM+X25519+ML-DSA) invocations under flood
(`handshake_dos_tests`, `handshake_dos_integration`):

| Attack | Volume | PQC invocations |
|---|---:|---:|
| Forged-cookie flood | 50 000 | **0** |
| Spoofed-source flood | 20 000 sources | **0** |
| Malformed flood | 6 000 | **0** |
| Replay flood | 10 000 | **1** |
| Distributed flood (global burst 25) | 5 000 sources | **25** |
| Legitimate flood (rate 20/10s⁻¹) | 1 000 | **20** |
| On-the-wire concurrent load (global burst 5) | 40 | **5** |

## 6.6 Resilience — record-layer loss ladder [measured]

`session_hardening_tests::lossy_reordered_replayed_channel_holds_invariants`
(in-process loss model; real `tc netem` is `[design]`):

| Injected loss | Delivered | Accepted exactly once | Replays injected | Replays rejected |
|---:|---:|---:|---:|---:|
| 10 % | 448 | 448 | 62 | 62 |
| 20 % | 389 | 389 | 73 | 73 |
| 30 % | 343 | 343 | 41 | 41 |
| 45 % | 277 | 277 | 49 | 49 |

100 % of delivered records open exactly once; 100 % of replays rejected; zero
false accepts, at every loss rate.

## 6.7 Assurance throughput [measured]

| Tool | Volume | Result |
|---|---:|---|
| Property suite (4 parsers + AEAD + window + cookie) | ~0.5 M seeded inputs | 0 panics / 0 leaks / 0 double-accepts / 0 false-accepts |
| cargo-fuzz `cookie_parse` | 4 809 352 runs | 0 crashes |
| cargo-fuzz `kernel_event_parse` | 5 954 610 runs | 0 crashes |
| cargo-fuzz `handshake_respond` | 2 097 152+ runs | 0 crashes |
| cargo-fuzz `session_open` | 1 crash → fixed → 3 127 261 runs | 0 (after fix) |
| Loom (exhaustive interleavings) | full state space | 0.65 s, cap proven |
| Miri (UB) | 12 pure-logic tests | 0 UB |
| Concurrency stress (real threads) | 16 threads × 20 000 (≈320 k lock cycles) | max in-flight = cap; 0 leaks |

## 6.8 Reproduce

```
cargo bench --bench demo_benchmarks
cargo test --release --locked
sudo scripts/ebpf_coverage_validate.sh          # BPF-capable host
scripts/run_miri.sh ; cargo test --test loom_model --release
cargo +nightly fuzz run cookie_parse -- -max_total_time=60
```
