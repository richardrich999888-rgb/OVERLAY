//! Syntriass overlay crate root.
//!
//! `cdylib` build -> `libsyntriass_overlay.so` for `LD_PRELOAD`.
//! `rlib` build   -> lets `cargo test` exercise the crypto unit tests.
//!
//! Interposed C symbols (`connect`, `send`, `recv`) live in `interceptor`.
//! All cryptography lives in `crypto` and is free of FFI/network side effects.
//! Runtime cipher agility (suite selection, negotiation, transcript binding)
//! lives in `crypto::{mod, generic, nist768, nist1024}`.

pub mod benchmarks;
pub mod crypto;
pub mod fd_state;
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
