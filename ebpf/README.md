# Syntriass eBPF data plane

Kernel-level universal interception — the replacement for LD_PRELOAD libc
interposition. Two implementations of the same idea live here:

| Path | Files | Status |
|---|---|---|
| **C + libbpf** (`cgroup/connect4`) | `c/connect4.bpf.c`, `c/loader.c`, `c/build.sh` | **validated on this host** — see `COVERAGE_REPORT.txt` |
| **Rust + Aya** (`sockops`) | `src/main.rs`, `src/maps.rs` | scaffold; requires `bpf-linker` (not present in the CI sandbox) — kept as the production Rust path |

The C/libbpf path is the one **measured** here, because it builds with only
`clang` + `libbpf-dev` (no `bpf-linker`, no nightly). The Aya path is the
idiomatic Rust deployment and shares the exact 56-byte `SockEvent` ABI
(`src/maps.rs`) with the userspace `kernel_native::KernelSockEvent`.

## Why this replaces LD_PRELOAD

LD_PRELOAD interposes libc symbols (`connect`, `send`, …). It is blind to any
process that does not call those symbols: a fully static binary, Go's runtime
(which issues raw syscalls), or anything doing `syscall(SYS_connect, …)`. The
`cgroup/connect4` hook runs inside the kernel's connect path, *below* libc, so it
sees **every** outbound connection in the cgroup and can allow, deny (fail-closed),
or redirect it. This is the same mechanism Cilium uses, which is why it maps
cleanly onto containers and Kubernetes (per-pod cgroup v2).

## Build + validate (BPF-capable host)

```
# deps: clang llvm libbpf-dev libelf-dev zlib1g-dev  (+ gcc go rustc python3 for the matrix)
ebpf/c/build.sh                       # -> connect4.bpf.o + loader
sudo scripts/ebpf_coverage_validate.sh   # measured coverage + enforcement
```

Requires root or `CAP_BPF`+`CAP_SYS_ADMIN`, a kernel with cgroup v2 and
`BPF_PROG_TYPE_CGROUP_SOCK_ADDR` (≥4.17). Not run in the default CI sandbox; the
captured run is `COVERAGE_REPORT.txt`. Full design + the measured table:
`docs/UNIVERSAL_INTERCEPTION.md`.
