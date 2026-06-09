# C-DAC (CDAC-SSDG) integration — compilation & alignment audit

SYNTRIASS v2 ↔ C-DAC System Software Development Group toolchains. All results
below are **measured on this host**; entries that require the C-DAC environment
(SYCL `parascc`, Singularity, OpenBLAS-ARM `.sif`, A64FX/SVE hardware) are marked
and were validated in **host-fallback** mode here.

## Host toolchain

| Tool | Present | Version |
|---|---|---|
| g++ | yes | 13.3.0 |
| clang++ | yes | 18.1.3 |
| cmake | yes | — |
| `parascc` (ParaS SYCL) | **no** | use CDAC-SSDG/ParaS-Compiler on target |
| Singularity / apptainer | **no** | required for the `.sif` containers |
| OpenBLAS-ARM (`.sif`) | **no** | CDAC-SSDG/hpc-containers on ARM/SVE host |

## 1. ParaS SYCL bridge — `src/accelerator/cdac_sycl_bridge.cpp` + `include/cdac_sycl_bridge.h`

`extern "C"` offload bridge accepting the strict 56-byte `CdacSockEvent` from the
Rust runtime, running an asynchronous `sycl::queue` (host ARM vector pipelines)
for out-of-band trace evaluation, with a `sycl::exception` fail-closed handler for
Singularity-sandbox runtime interrupts.

**Host-fallback compile (g++):**
```
$ g++ -std=c++17 -Iinclude -c src/accelerator/cdac_sycl_bridge.cpp
OK: compiled, all 56-byte static_asserts passed (8+8+16+16+2+2+2+2 = 56)
```

**Real SYCL build (on a ParaS host):**
```
parascc src/accelerator/cdac_sycl_bridge.cpp -Iinclude -DCDAC_ENABLE_SYCL -o libcdac_sycl_bridge.so
```

**Rust ↔ C++ link + round-trip (`cargo --features cdac-accel`):** `build.rs`
compiles the bridge via `cc`/g++ and links it; `src/accelerator.rs` hands it the
same `KernelSockEvent` bytes the eBPF RingBuf carries.
```
$ cargo test --release --features cdac-accel --lib accelerator
test accelerator::tests::evaluates_56_byte_event_through_the_bridge ... ok
test result: ok. 1 passed; 0 failed
```
The default `cargo build --release` is unchanged (build.rs is a no-op without the
feature): `Finished release profile in 16.20s`.

## 2. OpenBLAS-ARM (SVE) vector/matrix stress — `vector_matrix_stress.rs`

Standalone `rustc` program (per the C-DAC container workflow) with the exact
repository directives baked in:
```
singularity shell math_libraries/Openblas_arm.sif
export LD_LIBRARY_PATH=/home/user/openblas/lib/:$LD_LIBRARY_PATH
rustc -O --cfg openblas -L /home/user/openblas/lib/ -l openblas vector_matrix_stress.rs -o vms
```

**Host-fallback run (no OpenBLAS here):**
```
backend                 : host-fallback (naive triple loop)
GEMM size               : 256x256 f64
per-GEMM latency        : 4926.4 us  (6.81 GFLOP/s)
PSK fallback derive     : 47.0 us (control-plane, measured)
fallback / GEMM ratio   : 0.0095
```
The ~47 µs quantum-safe PSK EncryptedFallback derive is ≈1% of one 256×256 f64
GEMM on this scalar host path. The SVE-accelerated GFLOP/s figure requires the
OpenBLAS-ARM `.sif` on A64FX/Grace/Altra hardware (the `--cfg openblas` path calls
`cblas_dgemm` directly).

## 3. ASTViz / Clang AST audit — `scripts/nsm_ast_verify.sh`

Exports the Clang AST of the bridge as graph-able JSON (same LLVM front end as
CDAC-SSDG/Tools' ASTViz LibTooling) and proves the 56-byte contract is locked at
the abstract-syntax layer.
```
$ scripts/nsm_ast_verify.sh
AST exported: benchmarks/nsm_compliance_report/ast_visual_graph.json (830227 bytes)
StaticAssertDecl nodes in AST: 10
PASS: 56-byte alignment bounds are structurally locked at the AST layer.
```
The 10 `StaticAssertDecl` nodes = `sizeof==56`, `alignof==8`, and the 8 field
offsets (0/8/16/32/48/50/52/54) — a compiler-front-end proof for defense screening.

## Quality gates (this host)

```
cargo fmt --check                                  : clean
cargo clippy --all-targets -D warnings             : clean
cargo clippy --all-targets --features cdac-accel   : clean
cargo test (default)                               : 29 passed
bash -n scripts/nsm_ast_verify.sh                  : ok
```

## Honest boundary

These are integration bridges written to the **documented** C-DAC toolchain
contracts (`parascc` SYCL 2020, OpenBLAS-ARM `.sif`, ASTViz/Clang). The C-DAC
repositories were **not** fetched or linked from this sandbox; the SYCL offload,
Singularity execution, OpenBLAS-SVE acceleration, and ARM hardware paths run on a
provisioned C-DAC host. What is verified here: the 56-byte ABI lock (g++ + clang
AST), the Rust↔C++ FFI round-trip, and host-fallback execution of every component.
