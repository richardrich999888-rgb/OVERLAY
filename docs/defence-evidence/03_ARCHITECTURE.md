# 3. Architecture

Tags per `00_INDEX.md`. The overlay is a **split-plane** system: a kernel data
plane that intercepts/enforces, and a privileged userspace control plane that
runs the post-quantum handshake and hands keys to the kernel.

## 3.1 Component map

```
                         ┌──────────────────────────────────────────────┐
 workload (any runtime)  │  cgroup/connect4 eBPF  [measured]            │
   connect()  ───────────┼─►  observe → ringbuf event (KernelSockEvent) │  DATA PLANE
                         │   enforce → allow / deny(EPERM, fail-closed) │  (kernel)
                         └───────────────┬──────────────────────────────┘
                                         │ event / paused socket (fd)
                         ┌───────────────▼──────────────────────────────┐
                         │  control daemon  (src/bin/daemon.rs)          │
                         │   • anti-DoS admission gate  [tested/measured]│  CONTROL PLANE
                         │   • hybrid PQC handshake     [tested]         │  (userspace, privileged)
                         │   • identity (pinned / credential) [tested]   │
                         │   • bridge keys → kTLS        [implemented]   │
                         └───────────────┬──────────────────────────────┘
                                         │ setsockopt(SOL_TLS, …)
                         ┌───────────────▼──────────────────────────────┐
                         │  kernel TLS (kTLS)  [implemented]            │  DATA-PLANE CRYPTO
                         │   AES-256-GCM record encryption in-kernel    │  (kernel)
                         └──────────────────────────────────────────────┘
```

## 3.2 Modules (Rust crate) and status

| Module | Role | Tag |
|---|---|---|
| `crypto::{generic,nist768,nist1024}` | Hybrid X25519+ML-KEM handshake; AEAD directions | [tested] |
| `crypto::mod` (`IdentityMaterial`) | Ed25519+ML-DSA-65 identity; suite policy; identity cache | [tested] |
| `crypto::session` (`SecureSession`) | Sequenced, anti-replay, rekeyable record layer + lifecycle | [tested]/[measured] |
| `crypto::fallback` | Encrypted PSK degraded path (no plaintext) | [tested] |
| `handshake_guard` | Stateless-cookie anti-DoS gate; per-source + global caps | [tested]/[measured] |
| `identity` | Credential lifecycle: enrol/issue/rotate/revoke/expire/offline; `HybridSigner` | [tested] |
| `over_socket` | Over-socket handshake (gated) + kTLS handoff | [implemented]/[tested] |
| `kernel_native` | `KernelSockEvent` ABI; kTLS install primitives; `AvailabilityPosture` | [implemented] |
| `fd_passing` | `SCM_RIGHTS` fd passing (fail-closed) | [implemented]/[tested] |
| `fd_state` | per-fd state; config hot-reload watcher | [implemented] |
| `interceptor` | LD_PRELOAD path — **defence-in-depth fallback only** (superseded by eBPF) | [implemented] |
| `bin/daemon` | Control daemon (over-socket + fd-passing modes), gated | [implemented]/[tested] |

## 3.3 eBPF data plane (out-of-tree)

| Artifact | Role | Tag |
|---|---|---|
| `ebpf/c/connect4.bpf.c` | `cgroup/connect4` observer + fail-closed enforcer | [measured] |
| `ebpf/c/loader.c` | libbpf loader (attach to cgroup, ring-buffer poll, policy) | [measured] |
| `ebpf/src/` (Aya) | Production Rust loader path (needs `bpf-linker`) | [design/scaffold] |
| `scripts/ebpf_coverage_validate.sh` | Reproducible coverage+enforcement harness | [measured] |

The eBPF event shares the **same 56-byte `SockEvent`/`KernelSockEvent` ABI** the
userspace daemon already consumes, so the data plane is transport-agnostic to the
control plane (Unix-socket upcall today; eBPF ring buffer on a BPF host).

## 3.4 Key data flows

1. **Interception** [measured]: workload `connect()` → kernel `cgroup/connect4`
   → event to ring buffer; allow, or deny with `EPERM`.
2. **Admission** [tested/measured]: daemon issues a stateless cookie bound to the
   peer IP; only a returned valid cookie + per-source/global budget unlocks PQC.
3. **Handshake** [tested]: two-message hybrid exchange; mutual dual-signature;
   transcript-bound HKDF → directional AES-256-GCM keys.
4. **Identity** [tested]: peer keys come from a pinned config or a CA-verified
   credential (`identity::TrustStore::verify` → `VerifiedIdentity`).
5. **Record protection** [tested]: `SecureSession` adds sequencing, anti-replay,
   rekey, lifecycle; or kTLS takes the derived keys for in-kernel encryption.
6. **Degraded mode** [tested]: under degraded local posture, the encrypted PSK
   fallback preserves confidentiality (never plaintext).

## 3.5 Deployment topology

- **Single host** [measured]: attach `connect4` to the host cgroup root.
- **Containers/K8s** [design]: attach per-pod cgroup v2 (the Cilium model); the
  per-cgroup primitive is the one measured here.
- **Air-gap** [tested]: identity credentials/CRLs are self-contained signed bytes;
  the issuing authority runs disconnected.
- **ARM64 / sovereign** [design]: pure-Rust + portable C; no x86-only code in the
  crypto/control plane; hardware validation pending.

## 3.6 Build & dependency posture

- Main Rust crate: no new runtime crates added across the hardening tracks beyond
  promoting already-present transitive deps (`hmac`, `subtle`); `loom` is dev-only.
  [implemented]
- eBPF data plane is **out-of-tree** (C+libbpf, built by clang) and not part of
  `cargo build`, keeping the shipped `.so`/CI unaffected. [implemented]
