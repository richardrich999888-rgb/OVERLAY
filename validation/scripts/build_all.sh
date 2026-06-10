#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

cargo build --release --bin daemon --bin syntriassctl
cargo check --all-targets --offline || cargo check --all-targets

(
  cd ebpf
  cargo +nightly build --release --target bpfel-unknown-none -Z build-std=core
)

mkdir -p validation/bin

CGO_ENABLED=0 go build -o validation/bin/static_go_client ./validation/workloads/go_client
cargo build --manifest-path validation/workloads/rust_client/Cargo.toml --release
cp validation/workloads/rust_client/target/release/syntriass_static_rust_client validation/bin/static_rust_client
gcc -O2 -static -o validation/bin/direct_syscall_client validation/workloads/syscall_client/syscall_client.c
chmod +x validation/workloads/python_client/client.py validation/workloads/tcp_server.py

if command -v docker >/dev/null 2>&1; then
  docker build -t syntriass-validation-client -f validation/workloads/container_client/Dockerfile .
fi

echo "Build complete"
