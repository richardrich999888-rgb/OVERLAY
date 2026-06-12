# ARM64 Benchmarks — Phase 1

Companion to `docs/ARM64_VALIDATION.md`. Two strictly separated classes:

- **[measured] arch-independent** — byte counts and artifact sizes; identical on
  ARM64 and x86_64 (cross-checked), valid everywhere.
- **[measured-emulated]** — real ARM64 ISA execution under `qemu-aarch64-static`
  on an x86_64 host. *Correctness real; timings are the emulator's.* They are
  reported because they were measured, with the native column **[design]** until
  the native CI (`.github/workflows/arm64.yml`) or hardware plan (§5 of the
  validation doc) fills it. **No native estimates are given.**

Environment: x86_64 host (4 CPUs), QEMU 8.2.2 user-mode, rustc 1.94-class
toolchain, `--release --locked`.

## 1. Wire/artifact sizes — **[measured]**, arch-independent (cross-checked equal on x86_64)

| Artifact | Bytes |
|---|---:|
| Full in-band handshake (768) | 13 050–13 062 |
| **OOB runtime handshake** | **2 464** (−81.1 %) |
| ML-DSA pub+sig removed from runtime wire | 10 522 / handshake |
| KEM-only projection envelope (768/1024) | 2 348 / 3 212 |
| Enrollment request / credential | 5 381 / 5 409 |
| Revocation list (3 serials) / recovery auth | 3 429 / 3 405 |
| aarch64 `daemon` binary (text+data+bss) | 2 262 247 |
| aarch64 `libsyntriass_overlay.so` | 1 756 136 |

## 2. Handshake & crypto latency — **[measured-emulated]** (native: **[design]**)

| Metric | ARM64 under QEMU | x86_64 native (reference) |
|---|---:|---:|
| OOB runtime handshake | 2 435 µs | 328 µs |
| Full in-band handshake | 11 267 µs | 1 846 µs |
| OOB improvement over full | **78.4 %** | 82.2 % |
| In-band p50/p99 (768) | 11.07 / 25.89 ms | (see `docs/…/demo` runs) |
| KEM-only p50 (768) | 2.15 ms | — |
| Enrollment / PoP verify | 4 379 / 1 460 µs | 642 / 215 µs-class |
| Issue credential / verify | 2 684 / 1 468 µs | — |
| Issue CRL / authorize recovery | 8 767 / 10 084 µs | — |

The **relative** OOB improvement (78–82 %) survives emulation because both
paths are equally slowed — corroborating the architecture-independence of the
protocol-level win. Absolute emulated numbers must not be quoted as ARM64
platform performance.

Observed emulation factor on this workload: **≈ 4–7× wall-clock vs native
x86_64** (oob bench binary: 5.06 s vs 1.17 s; per-handshake ≈ 6–7×). Stated for
context only — not an ARM64 prediction.

## 3. Throughput — **[measured-emulated]**, native **[design]**

| Metric | ARM64 under QEMU |
|---|---:|
| Plaintext loopback TCP | 1 065 MB/s (host kernel does the copying) |
| AES-256-GCM seal+open | 9 MB/s — **emulation floor**: QEMU TCG does not accelerate the ARMv8 crypto extensions; this is the single most distorted number and is *expected* to be orders faster on silicon. Measure natively; do not cite. |

## 4. Memory / CPU envelope — **[measured-emulated]**, includes the emulator

| Metric | ARM64 (incl. QEMU) | x86_64 native |
|---|---:|---:|
| oob-bench max RSS | 14.7 MiB | 3.6 MiB |
| CPU during bench | 99 % of 1 core | 99 % of 1 core |
| Daemon time-to-bind | 109 ms | ~10 ms-class |

The ARM64 RSS column contains QEMU's translation caches; treat as an upper
envelope of (process + emulator), not the process. Native RSS: **[design]**.

## 5. Policy engine on ARM64

BPF bytecode is architecture-independent; the kernel-side latencies measured in
the Policy Engine v2 workstream (lookup 343 ns, resolve 895 ns, quarantine
325 ns, push 2–9 µs — x86_64 kernel 6.18.5) have **no ARM64 equivalent measured
yet** (this host's kernel is x86_64). The objects compile cleanly with
`-D__TARGET_ARCH_arm64`, and `.github/workflows/arm64.yml` runs the same four
validators on the ARM64 runner kernel. Until that log exists, ARM64 kernel
policy numbers are **[design]**.

## 6. Reproduce

```sh
rustup target add aarch64-unknown-linux-gnu
apt-get install gcc-aarch64-linux-gnu qemu-user-static
export QEMU_LD_PREFIX=/usr/aarch64-linux-gnu
SYNTRIASS_EMULATED=1 cargo test  --release --locked --target aarch64-unknown-linux-gnu
cargo bench --locked --target aarch64-unknown-linux-gnu --bench oob_benchmarks
cargo bench --locked --target aarch64-unknown-linux-gnu --bench identity_benchmarks
cargo bench --locked --target aarch64-unknown-linux-gnu --bench demo_benchmarks
```
