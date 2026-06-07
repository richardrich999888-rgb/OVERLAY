//! Syntriass overlay crate root.
//!
//! `cdylib` build -> `libsyntriass_overlay.so` for `LD_PRELOAD`.
//! `rlib` build   -> lets `cargo test` exercise the crypto unit tests.
//!
//! Interposed C symbols (`connect`, `send`, `recv`) live in `interceptor`.
//! All cryptography lives in `crypto` and is free of FFI/network side effects.
//! Runtime cipher agility (suite selection, negotiation, transcript binding)
//! lives in `crypto::{mod, generic, nist768, nist1024}`.

pub mod crypto;
pub mod fd_state;
pub mod interceptor;
