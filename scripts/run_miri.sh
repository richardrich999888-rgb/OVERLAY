#!/usr/bin/env bash
#
# Miri UB check for the overlay's pure-logic / unsafe surface.
#
# HOST-ONLY: Miri requires a nightly toolchain + the `miri` component, which are
# NOT present in the CI sandbox. This script is the documented, reproducible way
# to run Miri on a provisioned host; it is NOT executed in CI and nothing claims
# its results there. See docs/FAIL_CLOSED_VALIDATION.md.
#
# Miri cannot execute FFI / syscalls, so the interceptor (LD_PRELOAD), fd_passing
# (sendmsg/recvmsg), kernel_native (setsockopt) and the daemon are out of scope;
# Miri targets the pure crypto + record-layer + admission-gate logic, where it
# detects undefined behaviour, data races, and invalid memory access in the
# `unsafe`-free and `unsafe`-light pure code paths.
set -euo pipefail

if ! rustup component list --toolchain nightly 2>/dev/null | grep -q 'miri.*installed'; then
    echo "Installing nightly + miri ..."
    rustup toolchain install nightly --component miri
fi

# Pure, Miri-compatible modules (no FFI/syscalls/threads-with-OS-rng).
TESTS=(
  "crypto::"
  "handshake_guard::"
)

for t in "${TESTS[@]}"; do
  echo "== cargo +nightly miri test ${t} =="
  MIRIFLAGS="-Zmiri-strict-provenance" cargo +nightly miri test --lib "${t}"
done

echo "Miri: no undefined behaviour detected in the pure logic surface."
