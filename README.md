# Syntriass Overlay: Enterprise & Sovereign PQC Runtime Fabric

> **Executive briefing for CISOs, venture investors, and regulators:** Syntriass
> Overlay is a drop-in software layer for upgrading legacy banking, defence, and
> critical-infrastructure TCP applications toward post-quantum-ready transport
> protection without changing application source code.

Syntriass is designed for organizations that need crypto-agility now: the
ability to introduce, test, and change cryptographic protection around existing
systems without waiting for multi-year rewrite cycles.

## For RBI, Q-SAFE-Oriented Reviews, and Financial Regulators

The RBI's Q-SAFE direction highlights the need for financial institutions to
understand cryptographic inventory, assess crypto-agility, and identify critical
systems exposed to quantum-era threats. Syntriass maps directly to that
operational problem: it gives teams a runtime control that can introduce
NIST-aligned hybrid cryptography around selected legacy TCP workflows while the
underlying application remains unchanged.

- **Crypto-agility by policy:** switching from `nist768` to `nist1024` is a
  configuration change in `SYNTRIASS_SUITE` or `/etc/syntriass/policy.toml`,
  not an application rewrite.
- **CBOM-friendly evidence:** the implementation names exact primitives,
  versions, suite IDs, hook surfaces, and verification harnesses so reviewers can
  map what cryptography is used and where.
- **Fail-closed audit posture:** missing identity material, unauthenticated
  peers, tampered records, policy mismatch, and unsupported stream-socket egress
  paths produce failure rather than plaintext fallback.

Syntriass is not a regulatory certification by itself. It is an engineering
control that can support crypto-agility demonstrations, pilot programs, and
technical evidence packs for quantum-safe readiness reviews.

## For Bank C-Suites and CISOs

Manually refactoring core legacy codebases to add quantum-safe transport
security can consume years of specialist engineering time and create operational
downtime risk. Syntriass reduces that integration friction by moving protection
to the process runtime layer.

- **Zero-touch application integration:** deploy with `LD_PRELOAD`; the
  protected application binary and source code remain unchanged.
- **Operational continuity:** the app continues to use normal socket and
  file-descriptor APIs while the overlay transforms wire traffic into
  authenticated encrypted records.
- **Active enforcement:** this is not passive monitoring. If a peer is
  untrusted, a frame is malformed, a record is tampered, or a bypass syscall is
  used on a protected stream socket, Syntriass fails closed.
- **Measurable outcome:** the verification harness captures real wire bytes and
  proves that protected application markers are absent from overlay traffic.

## For Venture Capital and Strategic Buyers

Post-quantum migration creates a software modernization gap: enterprises must
prepare for quantum-era cryptographic risk faster than they can rewrite every
legacy application. Syntriass targets that gap with a software-only runtime
fabric that can be licensed, deployed, tested, and expanded across controlled
fleets.

- **Friction arbitrage:** customers avoid immediate full rewrites while still
  creating a concrete quantum-safe migration path for selected high-value TCP
  workflows.
- **High-leverage deployment model:** Rust implementation, process-local
  loading, policy-pinned suites, and deterministic verification harnesses reduce
  the amount of bespoke consulting needed for each pilot.
- **Enterprise expansion path:** start with controlled enclaves or legacy
  service pairs, then expand to broader secure transport overlays as operators
  validate identity provisioning, observability, and runtime compatibility.

The commercial value is not "encryption as a feature." It is reducing the time,
cost, and operational disruption required to move legacy systems toward
identity-bound, post-quantum-hybrid transport protection.

---

# Syntriass Overlay

Syntriass Overlay is a defence-oriented runtime encryption layer for protecting
legacy TCP applications in controlled Linux/glibc environments. It uses
`LD_PRELOAD` libc interposition to wrap ordinary POSIX stream-socket traffic in
an authenticated hybrid post-quantum tunnel without requiring changes to the
application binary.

The product is built for defensive network protection: reduce plaintext exposure
on internal links, harden legacy services that cannot be modified quickly, and
fail closed when identity, policy, framing, or cryptographic verification does
not match the configured trust policy.

## Product Description

Many operational systems still depend on applications that speak plaintext over
TCP or rely on inconsistent transport security. Rewriting those applications is
often slow, risky, or impossible. Syntriass Overlay provides a process-local
security control that sits between the application and libc socket calls.

From the application's perspective, it still calls `connect`, `send`, `recv`,
`write`, `read`, `sendmsg`, or related APIs. From the network's perspective,
the bytes are Syntriass overlay frames carrying authenticated encrypted records.

Syntriass is intended for deployments where both peers are controlled, identity
material can be provisioned out of band, and the operator wants a strict
fail-closed runtime layer rather than a permissive best-effort shim.

## Unique Selling Proposition

Syntriass Overlay's USP is that it gives defence teams a fail-closed,
post-quantum-ready transport protection layer for legacy TCP applications
without requiring application rewrites.

Most legacy-protection approaches force a tradeoff: either modify the
application, place trust in an external network appliance, or accept partial
coverage where some file-descriptor operations can still leak plaintext.
Syntriass takes a different position: it runs inside the protected process,
interposes the libc socket surface the application already uses, authenticates
both peers with classical and post-quantum identity signatures, and blocks
unsupported stream-socket egress paths instead of falling back to plaintext.

The differentiator is not just encryption. The differentiator is **runtime
enforcement**:

- No source-code changes for the protected legacy application.
- Hybrid classical plus post-quantum key exchange.
- Dual Ed25519 plus ML-DSA-65 peer authentication.
- Process-pinned suite policy with no downgrade path.
- Fail-closed behavior for tampering, unauthenticated peers, malformed frames,
  policy mismatch, and unsupported egress syscalls.
- Fork-after-connect nonce-reuse protection for inherited active descriptors.
- Wire-level proof harnesses showing that captured traffic is nonempty and the
  protected plaintext marker is absent.

In one sentence: **Syntriass turns an unmodified legacy TCP process into an
identity-bound, post-quantum-hybrid, fail-closed encrypted endpoint with tested
protection against common runtime bypass paths.**

## Business Use Cases

Syntriass Overlay is aimed at organizations that need to raise the security
level of existing TCP systems without waiting for a full application rewrite.

| Environment | Business need | Syntriass outcome |
| --- | --- | --- |
| Defence networks | Protect sensitive service-to-service traffic inside controlled enclaves | Plaintext TCP is replaced with authenticated encrypted overlay records |
| Critical infrastructure | Harden legacy operational services without changing brittle application code | Runtime transport protection can be added through process launch policy |
| Defence contractors | Reduce exposure of engineering, logistics, telemetry, and mission-support data | Wire captures no longer reveal protected application payloads |
| Secure labs and test ranges | Isolate experiments and prototypes from passive network observation | Overlay traffic remains opaque while the legacy app interface stays unchanged |
| Government modernization programs | Bridge old systems into post-quantum migration plans | Hybrid classical plus post-quantum key exchange and identity authentication are introduced at the runtime layer |
| Red/blue evaluation ranges | Prove whether a legacy application leaks data on the wire | Harnesses compare baseline plaintext leakage against protected overlay traffic |

## Financial Arbitrage and Competitive Advantages

The post-quantum transition is not only a cryptographic procurement problem. For
legacy estates, the largest blockers are engineering labor, operational downtime,
recertification risk, and the practical difficulty of changing systems that
already run critical workflows. Syntriass is designed to reduce those transition
costs by moving transport protection into a controlled process runtime layer.

### Cost-Effectiveness: TCO Pressure Points

The table below frames the cost categories operators should evaluate when
comparing runtime overlay deployment against manual rewrites or network
appliances. The actual financial values depend on fleet size, certification
scope, deployment geography, and assurance requirements.

| Expense category | Manual application refactoring | Hardware or network gateway approach | Syntriass runtime overlay |
| --- | --- | --- | --- |
| Engineering labor | Requires source-code changes, protocol redesign, regression testing, and application-owner coordination | Requires network design, routing changes, appliance integration, and operational handoff | Keeps the application binary unchanged and moves protection to launch policy and identity provisioning |
| Downtime risk | High during staged migrations, cutovers, and rollback planning | Medium to high during routing, topology, or gateway maintenance windows | Lower for controlled pilots because protection is applied at process start with `LD_PRELOAD` |
| Certification impact | Application changes may trigger new safety, banking, or defence review cycles | Appliance certification may not cover host-local or process-local plaintext exposure | The original application binary remains untouched; overlay assurance is evaluated separately |
| Coverage boundary | Strong when fully implemented, but slow across large legacy estates | Strong at chokepoints, but blind to traffic that never crosses the gateway | Protects covered libc stream-socket operations inside the process and fails closed on known bypass syscalls |
| Deployment footprint | No new hardware, but high engineering dependency | Requires appliance capacity, rack space, power, and network management | Software-only shared object plus policy and identity material |
| Crypto-agility | Depends on every modified application adopting the new suite | Depends on gateway vendor lifecycle and topology | Suite selection is policy-pinned and can be changed without rewriting the protected application |

The economic outcome is a smaller and more controlled migration surface:
operators can protect selected high-value TCP workflows first, prove wire
opacity with the verification harness, and then expand deployment as identity
provisioning and operational compatibility are validated.

### Exclusive Competitive Advantages

Syntriass is not positioned as a generic VPN, packet appliance, or cloud scanner.
Its advantage is process-local enforcement: the overlay sits where the legacy
application touches libc, before plaintext leaves through covered stream-socket
paths.

#### Mixed-I/O Plaintext Leak Prevention

Legacy applications frequently mix `send`, `write`, `writev`, `sendmsg`, and
Linux shortcut paths such as `sendfile` or `splice`. A gateway can only protect
bytes that reach it, and a partial shim can miss alternate file-descriptor
operations.

Syntriass routes covered read/write socket operations through the same
cryptographic state machine and fails closed on unsupported egress syscalls when
they target a tracked stream socket. That gives operators a concrete enforcement
property: known mixed-I/O bypass attempts do not silently downgrade to plaintext.

#### Fork-Aware Cryptographic Invariant Protection

User-space runtime overlays must account for `fork()`. A child process can
inherit active keys and counters from the parent, and a careless implementation
could let both processes seal records under the same AEAD nonce sequence.

Syntriass stamps file-descriptor state with the owning process ID and checks that
owner before send or receive operations. If an inherited active session is used
from the wrong process, the descriptor fails closed before additional records are
sealed. This preserves the nonce uniqueness invariant that AES-GCM depends on.

#### Sovereign and Disconnected Deployment Fit

Some defence, banking, and critical-infrastructure environments cannot rely on a
cloud control plane for core transport security. Syntriass is designed as a local
Linux/glibc runtime component: it does not require telemetry, internet access, or
an external key-management service to operate after identity material and policy
are provisioned.

That makes it suitable for controlled pilots in air-gapped labs, sovereign
enclaves, tactical test ranges, and other environments where external service
dependencies are prohibited or operationally unacceptable.

## Defence Outcomes

A successful Syntriass deployment produces concrete defensive outcomes:

- Network captures show nonzero overlay traffic but not the protected plaintext
  marker or application payload.
- The application continues to receive and send ordinary plaintext through its
  existing APIs.
- Unauthenticated peers are rejected before plaintext reaches the application.
- Tampered handshakes and tampered records fail closed.
- Policy mismatch prevents silent downgrade.
- Forked child processes cannot reuse inherited AES-GCM nonce counters.
- Alternate egress syscalls cannot write plaintext onto protected stream
  sockets.

The operational result is a measurable reduction in plaintext exposure for
legacy TCP workflows while preserving the application behavior operators already
depend on.

## Novelty

Syntriass is novel because it combines several controls that are usually handled
separately:

- Runtime socket interposition for unmodified applications.
- Authenticated hybrid classical plus post-quantum key exchange.
- Dual classical and post-quantum identity signatures.
- Process-pinned suite policy with no downgrade path.
- Fail-closed syscall coverage for common plaintext bypass routes.
- Fork-aware AEAD nonce protection for inherited file descriptors.
- End-to-end relay tests that prove opacity by inspecting captured wire bytes.

The important distinction is not only that the tunnel is post-quantum hybrid.
The stronger property is that the runtime layer is designed to fail closed when
applications attempt alternate fd operations that would otherwise bypass the
cryptographic path.

## Critical Defence Problems Solved

Syntriass addresses several high-priority defence problems:

- **Legacy plaintext exposure:** many mission, logistics, lab, and industrial
  systems still move sensitive data over ordinary TCP.
- **Slow modernization cycles:** replacing legacy applications may take years;
  Syntriass can protect selected traffic without source-code changes.
- **Harvest-now, decrypt-later risk:** adversaries can record today's encrypted
  traffic and wait for future cryptanalytic capability. Hybrid post-quantum
  key exchange reduces that long-term confidentiality risk.
- **Weak peer identity:** anonymous encryption is not enough for controlled
  defence environments. Syntriass requires explicit peer public-key trust.
- **Downgrade risk:** process-pinned policy and suite equality checks prevent a
  peer or intermediary from silently forcing a weaker suite.
- **Plaintext bypass through mixed I/O APIs:** legacy programs often mix
  `send`, `write`, `sendmsg`, `sendfile`, or `splice`. Syntriass covers or
  blocks those paths for stream sockets.
- **Fork-after-connect nonce reuse:** inherited active sessions are failed
  before a child can seal a record with duplicated counters.

## Why This Matters for the Next Five Years

For the 2026-2031 defence planning window, post-quantum transition is no longer
only a research topic. High-value networks need migration paths that can protect
existing systems while application teams work through slower modernization
cycles.

This class of control becomes operationally mandatory for high-assurance
environments because:

- Sensitive traffic captured today may remain valuable for years.
- Legacy applications will outlive the first phase of post-quantum migration.
- Defence systems need cryptographic agility without waiting for every vendor
  or internal application owner to ship new code.
- Identity-bound transport protection is required to prevent unauthenticated
  systems from joining trusted workflows.
- Fail-open runtime behavior is unacceptable for mission and critical
  infrastructure networks.

Syntriass does not claim to replace native secure transports in new
applications. Its role is to close the gap for systems that must continue
operating while defence organizations move toward post-quantum, identity-bound,
fail-closed network security.

## Defence Use Cases

- Protect legacy TCP services in enclaves, labs, test ranges, or private
  operational networks.
- Add wire opacity to applications that cannot be immediately upgraded to a
  native secure transport.
- Enforce peer identity at process startup using pre-distributed public keys.
- Detect and reject tampered handshakes, unauthenticated clients, and malformed
  records before application plaintext is delivered.
- Block common plaintext bypass paths such as `sendto`, `sendfile`, and
  `splice` on protected stream sockets.

This is a defensive runtime control. It is not an exploit framework, scanner,
traffic injector, or offensive tool.

## Technical Architecture

Syntriass Overlay builds a `cdylib` shared object:

```text
target/release/libsyntriass_overlay.so
```

That object is loaded into a target process with `LD_PRELOAD`. It resolves the
real libc symbols through `dlsym(RTLD_NEXT, ...)`, then interposes selected
socket and file-descriptor functions.

The core runtime components are:

```text
src/crypto/        hybrid handshake, identity authentication, AEAD records
src/fd_state.rs    per-fd state machine, bounded buffers, global registry
src/interceptor.rs libc hook implementations and fail-closed I/O paths
```

Each tracked file descriptor has an `FdState`:

```text
InitiatorAwaitingServerHello
ResponderAwaitingClientHello
Active(SessionKeys)
Failed
```

Once a descriptor reaches `Active`, application plaintext is sealed into
AES-256-GCM records before real socket transmission. Incoming records are
reassembled from the byte stream, authenticated, decrypted, and returned to the
application as ordinary plaintext reads.

## Cryptographic Construction

Each protected session uses an authenticated hybrid key exchange:

- X25519 ephemeral Diffie-Hellman
- ML-KEM-768 for suite `0x01`, or ML-KEM-1024 for suite `0x02`
- Ed25519 long-term identity signatures
- ML-DSA-65 long-term identity signatures
- HKDF-SHA256 directional session-key derivation
- AES-256-GCM record encryption and authentication

The design combines classical and post-quantum mechanisms for both key
agreement and peer authentication. The handshake is not anonymous: both peers
must be provisioned with local signing seeds and the exact public keys of the
peer they trust.

## Peer Authentication

Both `ClientHello` and `ServerHello` are signed. The responder validates the
initiator's identity before accepting the handshake. The initiator validates the
responder's identity before deriving usable application traffic keys.

Identity uses two signature systems:

```text
Ed25519     classical identity signature
ML-DSA-65   post-quantum identity signature
```

Missing identity material, malformed keys, unknown peer keys, bad signatures, or
tampered transcripts transition the descriptor to `FdPhase::Failed`. Application
plaintext is not delivered on failed sessions.

## Suite Policy

The active cipher suite is resolved once per process and pinned:

1. `SYNTRIASS_SUITE`, if set
2. `/etc/syntriass/policy.toml`, if present
3. Default: `nist768`

Supported values:

| Policy token | Suite ID | KEM |
| --- | --- | --- |
| `nist768`, `768`, `0x01` | `0x01` | ML-KEM-768 |
| `nist1024`, `1024`, `0x02` | `0x02` | ML-KEM-1024 |

There is no legacy plaintext suite, no anonymous suite, and no wire-negotiable
downgrade. If the initiator and responder policies do not match, the session
fails closed.

Example:

```toml
suite = "nist768"
```

## Identity Provisioning

### Identity Provisioning Specifications

Identity key packages require exact byte bounds. The system accepts raw 32-byte
cryptographic seeds for local generation, and expects fully formed,
uncompressed NIST public keys for peer verification.

| Configuration Variable | Key Type | Raw Size | Representation in TOML/Env |
| --- | --- | --- | --- |
| `SYNTRIASS_ED25519_SEED_HEX` | Ed25519 Seed | 32 Bytes | 64 Hex Characters |
| `SYNTRIASS_MLDSA65_SEED_HEX` | ML-DSA-65 Seed | 32 Bytes | 64 Hex Characters |
| `SYNTRIASS_PEER_ED25519_PUB_HEX` | Ed25519 Public | 32 Bytes | 64 Hex Characters |
| `SYNTRIASS_PEER_MLDSA65_PUB_HEX` | ML-DSA-65 Public | 1,952 Bytes | 3,904 Hex Characters |

Equivalent file configuration:

```toml
ed25519_seed = "<32-byte seed as 64 hex characters>"
mldsa65_seed = "<32-byte seed as 64 hex characters>"
peer_ed25519_public = "<32-byte public key as 64 hex characters>"
peer_mldsa65_public = "<1952-byte public key as 3904 hex characters>"
```

The file path is:

```text
/etc/syntriass/identity.toml
```

The helper binary derives public keys from local seeds:

```bash
cargo run --release --bin syntriass-identity -- \
  <ed25519-seed-hex> <mldsa65-seed-hex>
```

## Runtime Data Flow

Outbound flow:

```text
application plaintext
  -> intercepted send/write/writev/sendmsg path
  -> fd registry lookup or stream-socket adoption
  -> authenticated handshake if not active
  -> SessionKeys::seal()
  -> Syntriass frame
  -> real libc send() or write()
  -> network
```

Inbound flow:

```text
network
  -> real libc recv() or read()
  -> wire buffer
  -> frame reassembly
  -> suite/type validation
  -> SessionKeys::open()
  -> plaintext buffer
  -> application recv/read/readv/recvmsg result
```

If any required step fails, the fd state becomes `Failed` and later operations
return an error rather than falling back to plaintext.

## Interposed APIs

Encrypted stream pipeline:

```text
connect
send
recv
write
read
writev
readv
sendmsg
recvmsg
close
```

Fail-closed alternate egress paths:

```text
sendto
sendmmsg
sendfile
sendfile64
splice
```

For stream sockets, these alternate egress calls return `EOPNOTSUPP` because
their native semantics cannot safely preserve overlay framing and encryption.
For non-stream descriptors, they pass through to libc.

## Fail-Closed Controls

Syntriass is designed to prefer connection failure over plaintext leakage.

Implemented fail-closed controls include:

- Missing or malformed suite policy fails closed.
- Missing or malformed identity material fails closed.
- Untrusted peer identity fails closed.
- Bad Ed25519 or ML-DSA-65 signatures fail closed.
- Cross-suite mismatch fails closed.
- Tampered records fail AEAD verification and fail closed.
- Oversized or invalid frame lengths fail closed.
- Bounded receive and write buffers limit memory-exhaustion exposure.
- Unsupported egress syscalls on stream sockets fail closed.
- Fork-inherited active sessions fail closed before record sealing.

## Fork-After-Connect Protection

AES-GCM safety depends on never reusing a key and nonce pair. A process that
forks after establishing a connection can inherit active session keys and record
counters. If the child writes on the inherited fd, it can otherwise reuse a
counter value already used by the parent.

Syntriass records the owner PID in each `FdState`. On every overlay send and
receive operation, the current PID is checked under the per-fd lock before
handshake progress, `seal()`, `open()`, or frame emission.

If the current PID differs from the owner PID:

```text
phase -> FdPhase::Failed
errno -> EPIPE
return -> -1
```

Transitioning to `Failed` drops active `SessionKeys`, and sensitive key material
is zeroized through the crate's zeroization paths. The parent process keeps its
own fd state and can continue using the connection.

## Frame Format

```text
u32 big-endian   body length
u8               suite_id
u8               type
[u8]             payload
```

Frame types:

```text
1  ClientHello
2  ServerHello
3  Data
```

The cleartext header identifies the suite and frame type. Data payloads are
AEAD-protected. Handshake transcript material and suite identity are bound into
the authentication and key schedule so tampering causes verification failure.

## Memory Safety and Key Handling

The release profile uses:

```toml
panic = "abort"
```

This avoids unwinding across FFI boundaries. Sensitive buffers and key material
use explicit zeroization where the crate owns those bytes, including session key
drop paths and mutable plaintext/wire buffers.

Stream reassembly buffers are bounded to reduce denial-of-service risk from
fragmented or malicious inputs.

## Build

Native Linux:

```bash
cargo build --release
```

Run unit tests:

```bash
cargo test --release
```

The production shared object is:

```text
target/release/libsyntriass_overlay.so
```

## Container Build on Apple Silicon

Use a Linux/glibc container to validate the preload behavior:

```bash
docker run --rm -t -v "$PWD":/w -w /w rust:1.85-slim-bookworm bash -lc '
  export PATH=/usr/local/cargo/bin:$PATH
  apt-get update >/dev/null
  apt-get install -y python3 build-essential binutils >/dev/null
  cargo build --release
  cargo test --release
  python3 tests/verify_wire.py
  SYNTRIASS_SUITE=0x02 python3 tests/verify_wire.py
'
```

## Running a Protected Application

Both endpoints need reciprocal identity configuration.

```bash
LD_PRELOAD="$PWD/target/release/libsyntriass_overlay.so" \
SYNTRIASS_SUITE=0x01 \
SYNTRIASS_ED25519_SEED_HEX=<local-ed25519-seed> \
SYNTRIASS_MLDSA65_SEED_HEX=<local-mldsa65-seed> \
SYNTRIASS_PEER_ED25519_PUB_HEX=<trusted-peer-ed25519-public> \
SYNTRIASS_PEER_MLDSA65_PUB_HEX=<trusted-peer-mldsa65-public> \
./your-legacy-program
```

## Verification Harness

The test suite includes both cryptographic unit tests and Linux runtime tests.

```bash
cargo test --release
python3 tests/verify_wire.py
SYNTRIASS_SUITE=0x02 python3 tests/verify_wire.py
python3 tests/failclosed_test.py
python3 tests/concurrency_test.py
python3 tests/fork_test.py
python3 tests/egress_test.py
python3 tests/characterize.py
```

The runtime tests verify:

- The baseline application leaks plaintext without the overlay.
- The same application sees correct plaintext with the overlay loaded.
- The relay captures nonzero overlay traffic.
- The plaintext marker is absent from captured overlay traffic.
- Tampered and unauthenticated connections fail closed.
- Concurrent connections complete without global-lock deadlock.
- A forked child contributes zero Data records on an inherited fd.
- `sendto` and `sendfile` fail closed on tracked stream sockets.
- Non-stream operations still pass through.

## Repository Layout

```text
Cargo.toml
policy.toml.example
identity.toml.example

src/
  lib.rs
  bin/syntriass-identity.rs
  crypto/
    mod.rs
    generic.rs
    nist768.rs
    nist1024.rs
  fd_state.rs
  interceptor.rs

tests/
  vulnerable_app.py
  verify_wire.py
  failclosed_test.py
  concurrency_test.py
  fork_test.py
  egress_test.py
  netimpair_test.py
  characterize.py
```

## Operational Boundaries

- Production target: Linux/glibc.
- macOS development can compile parts of the crate, but cannot validate Linux
  preload semantics.
- Static binaries, direct raw syscalls, custom runtimes, or non-libc network
  paths may bypass libc interposition.
- The product protects TCP stream sockets, not UDP or arbitrary IPC.
- Identity provisioning is external and must be handled by the operator.
- The RustCrypto `ml-kem` and `ml-dsa` crates are pinned; review upstream audit
  status before production deployment.
- This layer does not replace network segmentation, host hardening, endpoint
  monitoring, or application-level authorization.
- **Multi-threaded fork constraints:** the fork PID guard cleanly isolates and
  fails closed active descriptors inherited by a child process. However, because
  POSIX `fork()` copies only the invoking thread, any concurrent thread holding
  an internal registry, file descriptor state, allocator, or other process mutex
  at the moment of invocation can leave that lock permanently unavailable in the
  child. Syntriass is architected for single-threaded or pre-fork multi-process
  network daemons; running it inside multi-threaded applications that execute
  post-connect forks is an unsupported configuration.

## Status

Syntriass Overlay is a defensive runtime security product prototype with a
strict fail-closed posture over its covered Linux/glibc socket surface. It is
suitable for controlled evaluation and pilot environments where operators can
provision peer identity material and validate the runtime harness on the target
platform before deployment.
