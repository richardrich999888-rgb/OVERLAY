# Continuous fuzzing harnesses (HOST-ONLY — not run in the CI sandbox)

These are real `cargo-fuzz` / libFuzzer targets for the overlay's
attacker-controlled parsers and the responder. They are **not** part of the main
workspace (this directory is a standalone workspace root) and are **not** executed
in the CI sandbox, which has only a stable toolchain. Nothing in
`docs/DEFENCE_READINESS_REVIEW.md` claims these have been run here; the in-sandbox,
deterministic equivalent that *is* run here is `tests/fail_closed_properties.rs`.

## Required external infrastructure

- a **nightly** Rust toolchain (libFuzzer needs `-Z` flags + a sanitizer runtime);
- `cargo-fuzz` (`cargo install cargo-fuzz`);
- a Linux host with the libFuzzer runtime (bundled with the nightly `rust-src`).

## Run

```
rustup toolchain install nightly
cargo install cargo-fuzz

# from the repository root:
cargo +nightly fuzz run cookie_parse
cargo +nightly fuzz run kernel_event_parse
cargo +nightly fuzz run session_open
cargo +nightly fuzz run handshake_respond

# time-boxed CI-style run with ASan + a corpus:
cargo +nightly fuzz run cookie_parse -- -max_total_time=300
```

## Targets and the invariant each asserts

| Target | Surface | Invariant |
|---|---|---|
| `cookie_parse` | `handshake_guard::Cookie::from_bytes` | no panic; parses only at the exact wire length; re-serialization is canonical |
| `kernel_event_parse` | `kernel_native::KernelSockEvent::from_bytes` | no panic; canonical (idempotent) serialization |
| `session_open` | `crypto::SecureSession::open` | no panic; never returns the plaintext canary from adversarial input (fail closed) |
| `handshake_respond` | hybrid-PQC `respond()` | no panic; random bytes are never accepted as a trusted ClientHello |

A crash or assertion failure here is a defect to fix before fielding. Findings
should be reproduced as a deterministic case added to
`tests/fail_closed_properties.rs`.
