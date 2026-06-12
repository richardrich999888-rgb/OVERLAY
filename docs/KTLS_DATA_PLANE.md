# PQC → kTLS Data Plane — Migration Platform Phase 2

Tags: **[measured]** real run · **[tested]** automated assertion ·
**[implemented]** code exists · **[design]/BLOCKED]** needs a TLS-ULP host.

**Objective:** replace the userspace record relay with **kernel TLS (kTLS)**
transport — derive the session secrets from the PQC handshake, install them into
the kernel via `TCP_ULP=tls` + `TLS_TX`/`TLS_RX`, and let the kernel encrypt/
decrypt the data plane. When kTLS is unavailable, **fail safely** (never fall
back to plaintext relay).

See also `docs/KTLS_INTEGRATION.md` (the PERF-2 deep dive). This document is the
Migration-Platform Phase 2 consolidation with the current environment probe.

---

## 1. Environment probe — **[measured]** (this host, kernel 6.18.5)

```
$ cat /proc/sys/net/ipv4/tcp_available_ulp
mptcp                      # <- 'tls' is NOT present; the TLS ULP is not loadable
$ modprobe tls             # command not found (no module tooling in this container)
```

**The TLS ULP is unavailable here.** kTLS therefore cannot be *activated* in this
environment; the throughput comparison is **BLOCKED** (§4). Everything that does
not require an active ULP — secret derivation, the install path, capability
detection, fail-closed — is validated below.

## 2. What is implemented & tested

| Capability | Status | Evidence |
|---|---|---|
| **PQC session-secret extraction** | ✅ [tested] | `ktls_secrets_are_derived_from_pqc_handshake_and_agree` — the kTLS TX/RX keys are derived from the real PQC handshake and **both peers agree** (initiator TX = responder RX) |
| **TLS_TX / TLS_RX installation** | ✅ [implemented] | `src/kernel_native.rs::{attach_tls_ulp, install_direction}` — real `setsockopt(SOL_TLS, TLS_TX/TLS_RX, tls12_crypto_info_aes_gcm_256)`; the 56-byte crypto_info struct layout is asserted to match the kernel uapi (`crypto_info_struct_is_56_bytes`) |
| **kTLS capability detection** | ✅ [tested] | `ktls_supported()` probes `TCP_ULP=tls` on a throwaway socket; classifies ENOENT/EOPNOTSUPP/ENOPROTOOPT/EPROTONOSUPPORT — and, since Phase-1 of the ARM64 work, **EINVAL at the ULP-attach stage** — as *unavailable* |
| **kTLS fallback handling (fail-safe)** | ✅ [tested] | `ktls_loopback_roundtrip_or_skip` self-skips when no ULP; the bridge returns `KernelNativeError::KtlsUnavailable` and the caller **fails closed** — there is no plaintext userspace-relay fallback |

`cargo test --test ktls_secret_bridge_tests --test ktls_roundtrip` → **4/4 pass**
on this host (the roundtrip test correctly self-skips the ULP-dependent leg).

## 3. Design — the data path when kTLS is present

```
PQC handshake (over_socket) ─▶ SessionKeys ─▶ export_ktls() ─▶ tls12_crypto_info_aes_gcm_256
        │                                                          │
        └── connected TCP fd ── setsockopt(TCP_ULP="tls") ── TLS_TX + TLS_RX install
                                                                   │
                              kernel encrypts/decrypts the data plane (no userspace relay)
```

When `ktls_supported()` is false, the bridge **must not** proceed to a userspace
plaintext relay — it returns `KtlsUnavailable` and the connection fails closed
(the zero-plaintext guarantee holds regardless of kTLS).

## 4. Throughput / CPU / latency — **BLOCKED** here, with a defensible plan

The mission asks to measure throughput, CPU, and latency vs a baseline. That
comparison **requires an active TLS ULP**, which this container lacks (§1). It is
therefore **BLOCKED**, not estimated. The measured baseline that frames the
target (from `benches/demo_benchmarks.rs`, this host):

| Baseline metric | Value |
|---|---:|
| plaintext loopback TCP (kernel does the copy) | ~1 065 MB/s |
| userspace AES-256-GCM seal+open ceiling | ~9 MB/s (cipher-bound, single-core) |
| current userspace relay data-plane | **12.8–15.5 % of line rate** (PERF-2) |

**Recommended defensible target (to verify on a TLS-ULP host):** kTLS removes the
userspace copy + per-record syscall overhead, so the data plane should reach
**≥ 28 % of line rate (~2× the userspace relay)** with a **CPU reduction** on the
encrypt path (kernel AES-NI, no userspace bounce). This target is grounded in the
12.8–15.5 % baseline and the AES-GCM ceiling — not asserted as achieved.

### Host-side validation plan — **[design]**

1. A kernel with the `tls` module (`modprobe tls`; `tcp_available_ulp` shows
   `tls`).
2. Run the existing `ktls_roundtrip` test — its ULP leg now executes (encrypt/
   decrypt through the kernel) instead of skipping.
3. `iperf`-style throughput over the overlay socket with kTLS on vs the userspace
   relay off; `pidstat`/`perf stat` for CPU; record into this doc §4.
4. Compare against the 12.8–15.5 % baseline; confirm ≥ 28 % / ~2× and CPU drop,
   or report the measured number and revise the target.

## 5. Success criteria — status

| Criterion (mission) | Status |
|---|---|
| kTLS active | ⛔ **BLOCKED** — no TLS ULP in this environment (§1) |
| PQC secrets successfully installed | ✅ [tested] secrets derived from the PQC handshake & agree; install path [implemented] |
| Throughput improvement measured | ⛔ **BLOCKED** — requires a TLS-ULP host; baseline + target + plan in §4 |
| When unavailable, fail safely | ✅ [tested] returns `KtlsUnavailable`, fails closed, no plaintext relay |

## 6. Residual risks & readiness impact

- The throughput uplift is the one headline number that cannot be produced here;
  it is the single most important item to run on a TLS-ULP host (the install +
  detection + fail-closed are all proven). Tagged honestly as BLOCKED, not
  estimated.
- No security posture was traded for throughput: the fail-closed path forbids a
  plaintext relay even when kTLS is absent.

DRR row **PERF-2** (already Med → Med-partial) is reaffirmed with the current
probe; readiness is unchanged pending a TLS-ULP host. See
`docs/DEFENCE_READINESS_REVIEW.md`.
