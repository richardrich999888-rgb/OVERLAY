#!/usr/bin/env bash
#
# Miri UB check for the overlay's pure-logic / unsafe surface.
#
# Requires a nightly toolchain + the `miri` component (the script installs both
# via rustup if missing). Validated results for this tree are recorded in
# docs/FAIL_CLOSED_ASSURANCE.md.
#
# Miri cannot execute FFI / syscalls, so the interceptor (LD_PRELOAD), fd_passing
# (sendmsg/recvmsg), kernel_native (setsockopt) and the daemon are out of scope;
# Miri targets the pure crypto + record-layer + admission-gate logic, where it
# detects undefined behaviour, data races, and invalid memory access in the
# `unsafe`-free and `unsafe`-light pure code paths.
set -euo pipefail

if ! rustup component list --toolchain nightly 2>/dev/null | grep -q 'miri.*installed'; then
    echo "Installing nightly + miri ..."
    rustup toolchain install nightly --profile minimal --component miri
fi

# Pure, Miri-compatible modules (no FFI/syscalls). Heavier crypto modules run
# slowly under the interpreter (~minutes); the selection below is the surface
# where Miri adds value over the native test suite.
TESTS=(
  "handshake_guard::"
  "crypto::fallback"
  "crypto::session"
)

for t in "${TESTS[@]}"; do
  echo "== cargo +nightly miri test ${t} =="
  cargo +nightly miri test --lib "${t}"
done

echo "Miri: no undefined behaviour detected in the pure logic surface."
