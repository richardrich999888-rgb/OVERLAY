# Universal Interception — Architecture, Honest Status, and Roadmap

**Objective (DRDO/iDEX review item #1):** eliminate `LD_PRELOAD` as the *primary*
enforcement mechanism; enforce at the kernel via eBPF/Aya across glibc, musl,
static binaries, Go, Rust, direct syscalls, containers, and Kubernetes.

This document is written to be read by a kernel maintainer and a red-team
operator. It does **not** defend the current implementation. Every claim is
tagged **VERIFIED** (evidence on hand), **CI-GENERATED** (evidence produced by a
named CI job on a Linux runner), or **GAP** (not yet true).

Last updated: 2026-06-10. Baseline commit: see `git log` at time of reading.

---

## 1. The three planes that make up interception today

| Plane | Code | What it actually does |
|------|------|-----------------------|
| **A. Connection gate** | `ebpf/src/cgroup_connect.rs`, attached by `src/kernel/loader.rs` | `cgroup/connect4`+`connect6` hooks. **Default-deny**: a connect is allowed only if `POLICY_MAP` says ALLOW *and* the socket cookie has an established, unexpired session in `SESSION_MAP` (`session_established()`, `cgroup_connect.rs:211`). Otherwise `CGROUP_DENY`. Errors fail closed to DENY (`main.rs:63-76`). |
| **B. Detection upcall** | `ebpf/src/main.rs` `sock_ops` program → `EVENTS` ringbuf | On `ACTIVE/PASSIVE_ESTABLISHED`, emits a 56-byte `SockEvent` (cookie, cgroup, 4-tuple) for user space. |
| **C. PQC handshake + kTLS** | `src/over_socket.rs`, `src/kernel_native.rs` | Real X25519+ML-KEM handshake over the socket, then `setsockopt(SOL_TLS, ...)` installs AES-256-GCM kTLS; any failure shuts+closes the fd (`bridge_session_to_ktls`, fail closed). |

Plane A is the property that gives "universal" reach: the cgroup hook fires for
**every** process in the cgroup regardless of libc, language, or static linking,
because it is in the kernel's `connect()` path — not in userspace. That is the
correct architecture and it is the reason this is not "just `LD_PRELOAD` again."

---

## 2. Critical findings (this pass)

### 2.1 FIXED — the kernel-native path did not compile (TRL-blocking)

The entire Linux/Aya control-plane (`src/kernel/loader.rs`, `src/policy/engine.rs`,
`src/session.rs` `linux` modules) was written against a **newer Aya API than the
pinned `aya = 0.12.0`** and therefore **did not compile for any Linux target**.
Because all of it is `#[cfg(target_os = "linux")]`, a developer's macOS
`cargo build` excluded it and looked green, masking the defect.

Seven errors, now fixed:
- `aya::programs::CgroupAttachMode` does not exist in 0.12 (added later) — removed.
- `CgroupSockAddr::attach()` takes **one** argument in 0.12, not two — corrected.
- `HashMap::try_from(MapData)` — 0.12 implements `TryFrom<Map>`, not
  `TryFrom<MapData>`; pinned maps now open via
  `HashMap::try_from(Map::HashMap(MapData::from_pin(path)?))`.

**VERIFIED** on this host (macOS, cross-check, no cross-linker needed because
`cargo check`/`clippy` do not link):

```
cargo check  --target x86_64-unknown-linux-gnu  --lib --bins   # 0 errors, 0 warnings
cargo check  --target aarch64-unknown-linux-gnu --lib --bins   # 0 errors, 0 warnings  (ARM64)
cargo clippy --target {x86_64,aarch64}-unknown-linux-gnu -- -D warnings  # clean
```

**Risk if unfixed:** the marquee "kernel-native v2" capability could not be built
or shipped on the target OS; any reviewer running `cargo build` on Linux would
have hit a hard compile failure. **Operational impact:** zero kernel enforcement
in the field. **Guard added:** `.github/workflows/kernel-native.yml` job
`cross-compile` now type-checks + clippy-lints both Linux targets on every push,
so this class of "Linux-gated code rots because nobody cross-compiles it" cannot
regress silently again. The ARM64 leg of that matrix is also the first concrete
evidence for the sovereign/ARM64 objective.

### 2.2 PARTIAL — the connection gate (Plane A) does not *encrypt*; a user-space data path now does

**Update (increment 2):** the user-space half is now implemented. `src/proxy.rs`
is a transparent egress proxy that owns the redirected application connection,
runs the **real** over-socket initiator handshake to the remote peer
(`over_socket::initiator_handshake` — not the self-handshake), installs kTLS on
the **outbound** socket (`install_session_ktls`, borrowed-fd, fail-closed), and
splices `app ⇄ peer`. The redirect uses `SO_ORIGINAL_DST` populated by an
iptables `REDIRECT`/`TPROXY` rule (the standard Envoy/Istio mechanism), so it
needs **no untested eBPF `connect`-rewrite** to be deployable. **VERIFIED**
(host): `proxy::tests::splice_relays_bidirectionally` (bidirectional relay) and
`proxy::tests::proxy_fails_closed_when_ktls_unavailable` (the proxy reaches the
kTLS stage and fails closed on a non-kTLS host, never relaying plaintext). The
*encrypted-on-the-wire* success path is **CI-GENERATED** by the `kernel-matrix`
job on a kTLS-capable kernel. Remaining: pcap-prove ciphertext for every workload
row, and (optionally) the eBPF `connect`-rewrite as an iptables-free redirect.

The original finding, for the record:

`cgroup/connect4` returns ALLOW/DENY. When it ALLOWs, the application's socket
proceeds as an ordinary TCP socket. **Nothing in Plane A installs kTLS on that
socket**, because the cgroup-connect hook never gets the application's fd and the
daemon is not in the data path. So in the "policy allow + session present"
scenario, the *application's own bytes* would traverse the wire under whatever
the app does (plaintext, unless the app itself uses TLS).

Encryption (Plane C) currently only happens on sockets the **daemon owns** — the
`SYNTRIASS_OVERSOCKET_LISTEN` responder and the `SYNTRIASS_FD_PASSING_UDS`
(SCM_RIGHTS) modes (`src/bin/daemon.rs:108-137`). Planes A/B and Plane C are
**not connected**: the kernel detects and gates, but the bytes of an arbitrary
unmodified application are not transparently routed through the PQC+kTLS bridge.

This is the central honest limitation. Today the system is:
- a **real, universal, fail-closed egress gate** (deny-by-default per cgroup,
  bound to an out-of-band session), **plus**
- a **real PQC+kTLS tunnel** for connections explicitly handed to the daemon.

It is **not yet** transparent PQC encryption of an unmodified application's
traffic end-to-end. See §3 for the data-path design that closes this.

### 2.3 FIXED — the loader now attaches sock_ops and consumes `EVENTS`

**Update (increment 2):** `src/kernel/loader.rs` now loads + attaches
`syntriass_sock_handler` (`SockOps`) alongside `connect4`/`connect6`, and its
`run()` loop polls **both** ring buffers via `tokio::select!` — `AUDIT_RINGBUF`
(allow/deny audit → sink) and `EVENTS` (connection-established detection upcalls →
structured JSON). Plane B is no longer dead code. **VERIFIED**: compiles + clippy
`-D warnings` clean for x86_64 and aarch64 Linux. (In the iptables-REDIRECT proxy
architecture the `EVENTS` stream is visibility, not the enforcement critical path;
it becomes load-bearing if the eBPF fd-handoff alternative is adopted.)

### 2.4 PARTIAL — the kernel-event handshake is a self-handshake stand-in

`kernel_native::run_local_handshake` (and `session::run_authenticated_pqc_session`)
run **initiator and responder in the same process with the same identity** and
discard the server keys (`kernel_native.rs:272-284`, `session.rs:150-160`). The
honest, real two-party exchange is `over_socket::{initiator,responder}_handshake`.

**Update (increment 2):** the **encryption data path now uses the real peer
handshake** — `proxy::proxy_connection` calls `over_socket::initiator_handshake`
over the outbound socket, so unmodified-app traffic is tunneled with a genuine
two-party authenticated exchange, not the self-loop. The self-handshake remains
**only** on the legacy `complete_kernel_upcall` UDS path (which still receives
`fd = None` and is now superseded by the proxy for transparent enforcement); it
should be retired or relabelled a key-schedule probe.

---

## 3. Closing the gap: transparent data-path design

To make Plane A/B drive Plane C for unmodified apps, the daemon must come to own
(or proxy) the application's connection.

> **Implemented (increment 2):** the transparent proxy is built in `src/proxy.rs`
> and driven by an iptables `REDIRECT` + `SO_ORIGINAL_DST` (option 0 below) — the
> deployable, no-eBPF-rewrite path. Options 1–3 are eBPF-native alternatives that
> remove the iptables dependency.

0. **iptables `REDIRECT`/`TPROXY` + `SO_ORIGINAL_DST` (implemented).** A nat-OUTPUT
   rule scoped to the enforced cgroup bounces governed TCP to the local proxy
   port; the proxy recovers the intended destination via `getsockopt(SO_ORIGINAL_DST)`,
   dials it, runs the PQC handshake, installs kTLS, and splices. Same loopback-hop
   confinement note as below.

Three eBPF-native alternatives; recommended of these is the **transparent proxy
via `connect4` redirect**, because it needs no fd theft and works for
static/Go/musl/syscall workloads uniformly:

1. **Connect-redirect transparent proxy (recommended).** The `connect4`/`connect6`
   hook rewrites the destination to a local daemon listener (preserving the
   original dst in a map keyed by socket cookie). The app connects to the daemon;
   the daemon reads the intended destination from the map, dials the **remote
   Syntriass peer**, runs the over-socket PQC handshake to that peer, installs
   kTLS, and splices app↔peer. Universal (kernel-path), no per-language work, and
   the app's plaintext only ever touches the loopback hop to the local daemon.
   *Cost:* one extra local hop; the loopback segment must be confined (netns/loopback-only).
2. **`sockmap`/`sk_msg` redirect.** Attach the established socket into a `BPF_MAP_TYPE_SOCKMAP`
   and redirect payload to the daemon via `sk_msg`. No extra TCP hop, but more
   verifier-sensitive and kernel-version-dependent.
3. **fd hand-off (SCM_RIGHTS) from a sockops/`fentry` hook.** Already half-built
   (`fd_passing.rs`, `handle_passed_fd`); needs a kernel-side trigger that passes
   the established fd to the daemon UDS. Most invasive; weakest portability.

All three preserve the fail-closed invariant: if the daemon cannot establish a
PQC session, the connection is dropped, never bridged in clear.

---

## 4. Workload coverage — honest status

| Workload | Gate (Plane A) | Transparent encrypt (Plane C) | Evidence |
|----------|----------------|-------------------------------|----------|
| glibc (Python) | reachable | needs §3 | `validation/workloads/python_client` |
| static Go | reachable | needs §3 | `validation/workloads/go_client` (CGO_ENABLED=0) |
| static Rust | reachable | needs §3 | `validation/workloads/rust_client` |
| direct syscall (C, `-static`) | reachable | needs §3 | `validation/workloads/syscall_client` |
| container (host net, cgroup-parent) | reachable | needs §3 | `validation/workloads/container_client` |
| musl | reachable (kernel path) | needs §3 | **GAP**: add a musl client to the matrix |
| Kubernetes pod | design only | needs §3 | `deploy/kubernetes/` DaemonSet exists; **GAP**: no e2e |

"Reachable" = the cgroup hook fires for this workload class because enforcement is
in the kernel, not libc — this is the whole point and is **CI-GENERATED** by the
`kernel-matrix` job (deny-by-default + session-binding scenarios A–F across the
first five rows). "needs §3" now means: transparent *encryption* is delivered by
the `src/proxy.rs` data path (increment 2) and is exercised end-to-end on a
kTLS-capable kernel; the remaining work is to pcap-prove ciphertext for each row
in the matrix and add a musl client + a k8s e2e.

---

## 5. Evidence index

| Claim | Status | Source |
|------|--------|--------|
| Crypto core handshake/roundtrip/tamper/downgrade | VERIFIED | `cargo test --lib` → 26 passed (host) |
| Linux/Aya control-plane compiles (x86_64 + ARM64) | VERIFIED | cross-check, §2.1 |
| Loader attaches sock_ops + consumes EVENTS | VERIFIED (compiles, clippy clean, both targets) | §2.3 |
| Transparent proxy splice + fail-closed-without-kTLS | VERIFIED (host) | `cargo test --lib proxy::` → 2 passed |
| eBPF bytecode object builds | CI-GENERATED | `kernel-native.yml` job `ebpf-bytecode` |
| Deny-by-default + session-binding across 5 workloads | CI-GENERATED | `kernel-native.yml` job `kernel-matrix` → `validation/artifacts/latest/matrix.jsonl` + pcaps |
| kTLS handoff installs + fails closed | CI-GENERATED (needs kTLS-capable kernel) | `tests/ktls_roundtrip.rs` |
| Transparent PQC encryption of unmodified app | PARTIAL | user-space path done (`proxy.rs`); ciphertext-on-wire is CI-GENERATED on kTLS kernel |
| Two-host (real peer) PQC over WAN | GAP | requires a 2-node testbed, not a single runner |

---

## 6. TRL roadmap for this objective

- **TRL 4 (now):** kernel-native enforcement primitives exist and **compile** for
  x86_64 + ARM64; PQC+kTLS bridge proven in isolation; deny-by-default gate
  CI-tested across language/runtime workloads.
- **TRL 5 (in progress):** ✅ transparent proxy data path (`proxy.rs`, iptables
  REDIRECT + `SO_ORIGINAL_DST`); ✅ sock_ops attached + `EVENTS` consumed;
  ✅ real peer handshake on the encryption path (no self-loop). **Remaining:**
  run the matrix on a kTLS kernel and pcap-prove ciphertext for every workload
  row; add a musl client; stand up a 2-node testbed so the responder is a real
  remote peer, not loopback.
- **TRL 6 (target):** run the full matrix on a representative ARM64 sovereign
  build and a k8s DaemonSet e2e; resilience (packet-loss/jamming) and
  performance benchmarks under load; independent red-team attempt to bypass the
  gate (raw `AF_PACKET`, namespace escape, pre-cgroup connect) with documented
  results.

---

## 7. Reproduce the verified results

```bash
# Host (macOS or Linux): user-space crypto/session/policy/proxy logic
cargo test --lib                 # 28 tests incl. proxy splice + fail-closed
cargo test --lib proxy::         # just the transparent-proxy data-path tests

# Cross-check the Linux/Aya kernel-native control plane WITHOUT a Linux box
rustup target add x86_64-unknown-linux-gnu aarch64-unknown-linux-gnu
cargo check  --target x86_64-unknown-linux-gnu  --lib --bins
cargo check  --target aarch64-unknown-linux-gnu --lib --bins

# On a Linux runner: eBPF object + enforcement matrix (see kernel-native.yml)
cd ebpf && cargo +nightly build --release --target bpfel-unknown-none -Z build-std=core
sudo bash validation/scripts/run_matrix.sh   # produces validation/artifacts/latest/

# Transparent proxy (Linux, kTLS-capable kernel):
#   1. start the remote peer as an over-socket responder on the target service host
#   2. redirect governed egress into the local proxy and run the daemon proxy mode
sudo iptables -t nat -A OUTPUT -p tcp -m cgroup --path syntriass.slice \
     -j REDIRECT --to-ports 18443
SYNTRIASS_PROXY_LISTEN=127.0.0.1:18443 ./target/release/daemon
```
