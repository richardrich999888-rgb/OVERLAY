#!/usr/bin/env bash
# Build the Syntriass universal-interception eBPF data plane (program + loader).
#
# Requires: clang (BPF target), libbpf-dev, libelf, zlib. On Debian/Ubuntu:
#   apt-get install -y clang llvm libbpf-dev libelf-dev zlib1g-dev
#
# Produces, in this directory:
#   connect4.bpf.o   the BPF object (loaded into the kernel)
#   loader           the libbpf userspace loader
set -euo pipefail
cd "$(dirname "$0")"

ARCH_INC="$(dirname "$(find /usr/include -name types.h -path '*asm/types.h' 2>/dev/null | head -1)")"
ARCH_INC="${ARCH_INC%/asm}"

echo "== compiling connect4.bpf.c (clang -target bpf) =="
clang -O2 -g -Wall -target bpf -D__TARGET_ARCH_x86 \
    ${ARCH_INC:+-idirafter "$ARCH_INC"} \
    -c connect4.bpf.c -o connect4.bpf.o
llvm-strip -g connect4.bpf.o

echo "== compiling loader.c (libbpf) =="
clang -O2 -Wall loader.c -o loader -lbpf -lelf -lz

echo "OK: connect4.bpf.o + loader built"
