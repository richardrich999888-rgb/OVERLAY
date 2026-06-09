# Syntriass build orchestration — eBPF data plane

The eBPF program in [`../ebpf`](../ebpf) is an **out-of-tree** crate: it targets
`bpfel-unknown-none` and is *not* part of the main `syntriass-overlay` workspace,
so `cargo check`/`cargo test`/`cargo clippy` at the repo root never try to build
it. This keeps the user-space build green on hosts without a BPF toolchain.

This document is the build blueprint (there is intentionally no compiled `xtask`
binary, to avoid adding a member to the main workspace).

## Prerequisites (build host)

```bash
# Nightly toolchain + core sources for -Z build-std
rustup toolchain install nightly
rustup component add rust-src --toolchain nightly

# The BPF bytecode linker
cargo install bpf-linker
```

A Linux kernel with `CONFIG_BPF_SYSCALL`, `sockops` (cgroup/BPF_PROG_TYPE_SOCK_OPS)
and BPF ring-buffer support is required to *load* the result.

## Build the bytecode

From the **`ebpf/`** directory (its own workspace root):

```bash
cd ebpf
cargo +nightly build --release \
  --target bpfel-unknown-none \
  -Z build-std=core
```

Output ELF object:

```
ebpf/target/bpfel-unknown-none/release/syntriass-ebpf
```

The `[profile.release]` in `ebpf/Cargo.toml` (`panic = "abort"`, `lto = true`,
`opt-level = 3`, `codegen-units = 1`) keeps the object compact and free of
unwinding/panic machinery the eBPF verifier rejects.

## Loading (requires CAP_BPF / root)

Loading and attaching the program requires `CAP_BPF` (or root) on the host
kernel. The user-space loader consumes the object above; see the documented Aya
RingBuf consumer seam in [`../src/bin/daemon.rs`](../src/bin/daemon.rs):

```rust
// (requires the `aya` user-space crate + a built object + CAP_BPF)
let mut bpf = aya::Ebpf::load_file(
    "ebpf/target/bpfel-unknown-none/release/syntriass-ebpf",
)?;
// attach the `syntriass_sock_handler` sock_ops program to a cgroup, then
// consume the `EVENTS` RingBuf and feed each KernelSockEvent to the daemon.
```

## Struct ABI contract

The kernel `maps::SockEvent` and the user-space
`syntriass_overlay::kernel_native::KernelSockEvent` MUST stay byte-identical
(`#[repr(C)]`, 56 bytes, identical field order). Both sides carry compile-time
`const _: () = assert!(...)` guards (size/align/field offsets), and
`tests/layout_sanitization_tests.rs` checks the user-space side, so any drift is a
build failure rather than a silent wire mismatch.
