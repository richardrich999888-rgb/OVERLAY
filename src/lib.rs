//! Syntriass overlay crate root.
//!
//! `cdylib` build -> `libsyntriass_overlay.so` for `LD_PRELOAD`.
//! `rlib` build   -> lets `cargo test` exercise the crypto unit tests.
//!
//! Interposed C symbols (`connect`, `send`, `recv`) live in `interceptor`.
//! All cryptography lives in `crypto` and is free of FFI/network side effects.
//! Runtime cipher agility (suite selection, negotiation, transcript binding)
//! lives in `crypto::{mod, generic, nist768, nist1024}`.
//!
//! Fail-closed lint hardening: an ignored `Result`/`#[must_use]` value on a
//! security path (e.g. a dropped error from a seal/close/teardown) is a
//! fail-*open* bug, so a dropped must-use value is a hard error crate-wide.
//! See `docs/FAIL_CLOSED_VALIDATION.md` for the unsafe-code audit and the
//! property/concurrency assurance evidence.
#![deny(unused_must_use)]

#[cfg(feature = "cdac-accel")]
pub mod accelerator;
pub mod benchmarks;
pub mod crypto;
pub mod fd_passing;
pub mod fd_state;
pub mod handshake_guard;
// The interceptor's whole purpose is exporting `#[no_mangle]` libc symbol
// overrides (write/read/close/...). Under Miri those clash with the
// interpreter's built-in libc shims, so the module is compiled out for Miri
// runs; Miri targets the pure-logic surface (crypto, record layer, guard).
#[cfg(not(miri))]
pub mod interceptor;
pub mod kernel_native;
pub mod over_socket;
pub mod telemetry;

/// Starts the Linux configuration hot-reload worker.
///
/// The interceptor starts this lazily when the fd registry is initialized, but
/// embedding applications and tests can call this explicitly. On non-Linux
/// targets the worker reports that hot reload is unsupported and exits.
pub fn start_config_hot_reloader() {
    fd_state::start_config_hot_reloader();
}
