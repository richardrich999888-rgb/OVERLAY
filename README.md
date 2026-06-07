# syntriass-overlay

A **Linux-only** `LD_PRELOAD` proof-of-concept that transparently wraps a POSIX
stream socket in a **runtime-agile hybrid post-quantum tunnel** (X25519 + ML-KEM,
HKDF-SHA256 schedule, AES-256-GCM records) **without modifying the application**.

## Cipher agility (this revision)

The active suite is **late-bound** at process start and pinned for the process:

- `SYNTRIASS_SUITE` env var (e.g. `SYNTRIASS_SUITE=0x02`), else
- `/etc/syntriass/policy.toml` (`suite = "nist1024"`), else
- safe default: `nist768`.

Suites: `NistStandard768` (id `0x01`) and `NistStandard1024` (id `0x02`).
**There is no legacy/no-PQC suite and no wire-negotiable downgrade.**

### Negotiation = fail closed
The initiator proposes its policy suite in the ClientHello. The responder accepts
**only if** the proposed suite equals its own policy suite; otherwise it drops the
session. No silent downgrade (avoids the FREAK/Logjam class).

### Transcript binding
The negotiated `suite_id` is folded into the HKDF `info`, and also travels in the
clear in each frame header. A MITM that flips the suite byte produces a different
key schedule on the tampered side -> AEAD authentication fails -> session dropped.

## Frame format (single, unambiguous)

```
u32 big-endian   LENGTH of (suite_id + type + payload)
u8               SUITE_ID  (0x01=NIST-768, 0x02=NIST-1024)
u8               TYPE      (1=ClientHello, 2=ServerHello, 3=Data)
[u8]             PAYLOAD
```

## Layout

```
syntriass-overlay/
├── Cargo.toml
├── policy.toml.example
├── src/
│   ├── lib.rs              # crate root
│   ├── crypto/
│   │   ├── mod.rs          # trait, CipherSuite, policy reader, SessionKeys, tests
│   │   ├── generic.rs      # shared X25519+ML-KEM core (generic over KemCore) + tests
│   │   ├── nist768.rs      # suite 0x01
│   │   └── nist1024.rs     # suite 0x02
│   ├── fd_state.rs         # per-fd state machine (dynamic engine) + registry
│   └── interceptor.rs      # connect/send/recv hooks, framing, negotiation, blocking I/O
└── tests/
    ├── vulnerable_app.py
    └── verify_wire.py
```

## Honest status

- **Not compiled here.** This was written against the verified `ml-kem` 0.2.3 and
  `x25519-dalek` 2.0.1 APIs, but the author's environment had no Rust toolchain.
  **You must `cargo test` / `cargo build` to confirm.**
- **Known compile-risk points:** the two `try_from` conversions in
  `src/crypto/generic.rs` (encapsulation key and ciphertext). If the compiler
  reports an unsatisfied `TryFrom<&[u8]>` bound (RustCrypto/hybrid-array#114), the
  inline comments give the one-line fix (`ml_kem::array::Array::try_from`).
- `ml-kem` is itself **unaudited** (upstream says so). PoC only. Not "mathematically
  proven safe" — only the API shapes were verified against docs.rs.
- No peer authentication (no signatures/PSK): vulnerable to active MITM at handshake.
  Hardening = add ML-DSA signatures or a PSK. Documented, not done.
- Only `connect`/`send`/`recv` are hooked. `write`/`read`/`sendmsg` bypass the tunnel.

## Build & test (Linux, or in a container on Apple Silicon)

```bash
docker run --rm -it -v "$PWD":/w -w /w/syntriass-overlay \
  rust:1.78-slim-bookworm bash -lc '
    apt-get update && apt-get install -y python3 build-essential &&
    cargo test --release &&            # crypto agility + MITM + policy tests (no sockets)
    cargo build --release &&           # -> target/release/libsyntriass_overlay.so
    python3 tests/verify_wire.py       # end-to-end wire proof
  '
```

Native Linux:

```bash
cd syntriass-overlay
cargo test --release
cargo build --release
SYNTRIASS_SUITE=0x02 python3 tests/verify_wire.py   # exercise the 1024 suite
```
