#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
  echo "setup_ubuntu24.sh must run as root" >&2
  exit 1
fi

apt-get update
apt-get install -y --no-install-recommends \
  bash ca-certificates clang curl gcc git iproute2 iputils-ping jq \
  libc6-dev libelf-dev llvm make pkg-config python3 python3-venv \
  rustup tcpdump tshark wget xz-utils

if ! command -v go >/dev/null 2>&1; then
  apt-get install -y --no-install-recommends golang-go
fi

rustup default stable
rustup toolchain install nightly
rustup component add rust-src --toolchain nightly

if ! command -v bpf-linker >/dev/null 2>&1; then
  cargo install bpf-linker
fi

mkdir -p /sys/fs/cgroup/syntriass-validation
mkdir -p /sys/fs/bpf/syntriass

echo "Ubuntu 24.04 validation setup complete"
