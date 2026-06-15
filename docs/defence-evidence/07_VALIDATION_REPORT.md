# 7. Validation Report

Tags per `00_INDEX.md`. This is the consolidated test/validation inventory.
**133 automated tests pass** under `cargo test --release --locked` in this
environment, plus the host-only eBPF/Miri/Loom/fuzz runs recorded below.

## 7.1 CI gate (every commit) [tested]

```
cargo fmt --check                         # clean
cargo clippy --all-targets -- -D warnings # clean (+ #![deny(unused_must_use)])
cargo build --release --locked            # clean
cargo test --release --locked             # 133 tests pass, 0 fail
```

## 7.2 Automated test suites [tested]

| Suite | Focus | Tag |
|---|---|---|
| `crypto::*` unit (lib) | Handshake agility, transcript binding, tamper, identity pinning, record layer, fallback, **max-epoch overflow regression** | [tested] |
| `handshake_guard::*` unit | Cookie issue/admit, rate limit, global rate + concurrency caps, secret rotation, bounded maps | [tested] |
| `identity::*` unit | Enrol PoP, issue/verify, expiry, tamper, rotation, revocation, stale/forged CRL, offline, malformed | [tested] |
| `handshake_dos_tests` | Real `respond()` PQC-invocation counts under floods (in-process) | [tested]/[measured] |
| `handshake_dos_integration` | On-the-wire gated path; forged/replay/global-load | [tested]/[measured] |
| `identity_lifecycle_tests` | Credential drives the **real handshake**; expired/revoked block trust; air-gap | [tested] |
| `session_hardening_tests` | Loss-ladder (10/20/30/45 %), reorder, replay, rekey over the real handshake | [tested]/[measured] |
| `fail_closed_properties` | Canary/no-cleartext, tamper, parser robustness, anti-replay, cookie no-false-accept | [tested]/[measured] |
| `leakage_analysis` | Debug redaction, no keys on wire, no error reflection, no PSK on wire | [tested] |
| `concurrency_stress` | Real-thread cap-never-exceeded, no deadlock, poison fail-closed | [tested]/[measured] |
| `loom_model` | Exhaustive interleaving proof + TOCTOU negative control | [measured] |
| `chaos_orchestration` | Spawns the real daemon; kill mid-session ⇒ fail closed; mem pressure | [tested] |
| `over_socket_tests`, `fd_passing_bridge_tests`, `kernel_bridge_tests`, `ktls_roundtrip`, `layout_sanitization_tests`, `range_simulation`, `defense_scenario_tests` | v2 plumbing, ABI layout, fd passing, range sim | [tested] |
| Python integration (`tests/*.py`) | LD_PRELOAD wire/fail-closed/fork/egress (defence-in-depth path) | [tested] |

## 7.3 Host-only validation (run on provisioned hosts) [measured]

| Validation | Where | Result |
|---|---|---|
| **eBPF universal interception** | `scripts/ebpf_coverage_validate.sh` (kernel 6.18, root) | 7/7 runtimes + EPERM enforcement — `ebpf/COVERAGE_REPORT.txt` |
| **Miri (UB)** | `scripts/run_miri.sh` (nightly+miri) | 12 pure-logic tests, 0 UB |
| **Loom (concurrency)** | `cargo test --test loom_model` (loom dev-dep) | exhaustive, 3 tests, 0.65 s |
| **cargo-fuzz (libFuzzer+ASan)** | `fuzz/` (nightly+cargo-fuzz) | 16M+ runs; **1 bug found+fixed**, re-fuzzed clean |

## 7.4 Notable validation outcomes

- **A real fail-open bug was caught by fuzzing** (FC-1): `SecureSession::open`
  overflow-panicked on a record with attacker epoch `0xFFFF_FFFF`. Fixed,
  regression-tested (`max_epoch_record_fails_closed_without_overflow`), re-fuzzed
  3.1 M runs clean. [measured]
- **A real UB was caught by the unsafe audit**: a misaligned `&inotify_event`
  reference in `fd_state.rs`, fixed to `ptr::read_unaligned`. [implemented]
- **LD_PRELOAD blind spots proven**: the eBPF harness measured interception of
  static/Go/musl/direct-syscall connects that an LD_PRELOAD shim cannot see.
  [measured]

## 7.5 Validation gaps (honest) [design]

- kTLS in-kernel round-trip (`ktls_roundtrip` skips where the kernel lacks the TLS
  ULP in this sandbox).
- Real `tc netem` link (loss ladder is an in-process model here).
- ARM64, TPM/HSM, K8s, IPv6/UDP egress — see `05_RISK_REGISTER.md` / `08`.
- Independent external red-team / interop testing — `[future]`.

## 7.6 Reproduce everything

```
cargo fmt --check && cargo clippy --all-targets -- -D warnings
cargo build --release --locked && cargo test --release --locked
# host-only:
sudo scripts/ebpf_coverage_validate.sh
scripts/run_miri.sh
cargo test --test loom_model --release
cargo +nightly fuzz run cookie_parse -- -max_total_time=60
```
