# PQC → kTLS Secret Bridge (Phase 2)

Tags: **[measured]** real run · **[tested]** automated assertion · **[implemented]**
code exists · **[design]** specified, needs external infra.

**Objective:** replace the userspace record relay with a kernel-TLS (kTLS) data
plane — extract the session secrets from the PQC handshake, install `TLS_TX`/
`TLS_RX`, and let the kernel do the AEAD.

## 0. Capability — kTLS is unavailable here (BLOCKED on the kernel)

This environment has **no TLS ULP**: there is no `tls` kernel module, and
`kernel_native::ktls_supported()` returns **false** (`tests/ktls_roundtrip.rs`
prints `SKIP: kTLS ULP unavailable`). Therefore the kTLS **encrypt/decrypt
round-trip and the throughput benchmark cannot run here** — they are `[design]`
with the host-side plan in §5. **No throughput-improvement number is claimed**, in
line with the "no fabricated benchmarks" rule.

What *is* validated here (no kernel ULP needed) is the **secret bridge** itself.

## 1. The secret bridge — **[implemented]/[tested]**

| Step | Code | Status |
|---|---|---|
| Extract per-direction AES-256-GCM key + salt + IV from the PQC session | `SessionKeys::export_ktls` → `KtlsTrafficKeys` | [implemented]/[tested] |
| Pack into the kernel struct `tls12_crypto_info_aes_gcm_256` (56 B, layout-asserted) | `KtlsSecrets::from_traffic_secret`, `sys::Tls12CryptoInfoAesGcm256` | [implemented] |
| Install TX/RX via `setsockopt(SOL_TLS, TLS_TX/TLS_RX, …)` | `install_ktls_tx/rx/duplex` | [implemented] |
| Attach the ULP + bridge the established session, fail-closed on error | `attach_tls_ulp`, `bridge_session_to_ktls` | [implemented] |
| Bypass the userspace record path once kTLS is active | `over_socket::establish_and_bridge` hands the fd to the kernel after the handshake | [implemented] |

**Validated without the kernel ULP** (`tests/ktls_secret_bridge_tests.rs`,
3 tests, all pass):

| Property | Test |
|---|---|
| kTLS secrets are **derived from the PQC handshake** and **agree** across peers (initiator TX key == responder RX key, both directions; matching salt/IV) | `ktls_secrets_are_derived_from_pqc_handshake_and_agree` |
| Secrets pack into the kernel crypto_info (key/salt/IV copied, record seq starts at 0) | `traffic_secret_packs_into_kernel_crypto_info` |
| The bridge **fails closed** on a kernel with no TLS ULP (returns `Err`, tears the socket down) | `bridge_fails_closed_when_no_tls_ulp` → `Err(KtlsUnavailable)` |

So three of the four success criteria are met here: **the data plane is wired to
kTLS**, **secrets are derived from the PQC handshake**, and **fail-closed holds**.
The fourth — *throughput measurably improves* — is **BLOCKED** on the TLS ULP.

## 2. Current data-plane baseline — **[measured]**

From `cargo bench --bench demo_benchmarks` (this shared host, release):

| path | throughput | % of loopback line rate |
|---|---:|---:|
| plaintext loopback TCP (line-rate reference) | 1 535 MB/s | 100 % |
| AES-256-GCM seal+open (userspace AEAD ceiling) | 488 MB/s | 31.8 % |
| current overlay over-socket userspace path | **12.8–15.5 %** (≈ 197–238 MB/s) | 12.8–15.5 % |

The current path sits at 12.8–15.5 % of line rate; even a *pure* userspace AEAD
caps at ~32 % (488 MB/s). The gap from 32 % down to 12.8–15.5 % is the **userspace
record framing + per-record copy + syscall overhead** — exactly what kTLS removes
by doing the AEAD in the kernel on the existing socket.

## 3. Why kTLS should improve it (mechanism, not a measured claim)

With kTLS active the kernel encrypts/decrypts records inline on `send`/`recv`
(and can `sendfile` straight from page cache), eliminating: the userspace copy of
every record, the per-record `seal`/`open` call, and the framing roundtrip. The
AEAD itself is the same AES-256-GCM. So the expected ceiling moves from "userspace
AEAD minus framing overhead" (12.8–15.5 %) toward "kernel AEAD ≈ cipher rate"
(~32 % of loopback line rate, ~488 MB/s) and beyond for bulk transfer.

## 4. Recommended defensible target (since the original cannot be measured here)

The brief asks to "compare against current 12.8–15.5 % line rate." Because real
kTLS cannot be exercised in this environment, the honest, measurable target to set
for the kTLS-capable host is:

> **Target: kTLS data plane ≥ 28 % of loopback line rate (≈ 430 MB/s), i.e. ≥ ~2×
> the current 12.8–15.5 %**, with the AES-256-GCM userspace ceiling (31.8 %,
> 488 MB/s) as the practical asymptote and bulk `sendfile` transfers expected
> higher. To be confirmed `[measured]` on a TLS-ULP host via §5.

This is grounded in the measured baseline (§2): it claims ~2× by removing the
userspace framing/copy that separates 12.8–15.5 % from the 31.8 % AEAD ceiling —
not an arbitrary number.

## 5. Host-side validation plan (kTLS-capable host) [design]

On a Linux host with the `tls` module (`modprobe tls`; most distro kernels):

```
modprobe tls && cat /proc/modules | grep '^tls'    # confirm the ULP
cargo test --test ktls_roundtrip -- --nocapture     # real kTLS encrypt/decrypt round-trip
# throughput A/B on the same host:
#   baseline: overlay userspace record path  (current 12.8-15.5%)
#   kTLS:     bridge_session_to_ktls(fd, &keys) then bulk transfer + sendfile
# record: throughput (MB/s + % line), CPU%, latency; compare to §2/§4.
```

`tests/ktls_roundtrip.rs` already drives the real install + encrypt/decrypt and
**auto-skips** where the ULP is absent (as here); it becomes the `[measured]`
kTLS proof on that host. Re-run and paste the numbers into the §4 table to close
the throughput criterion.

## 6. Status & residual

- **COMPLETED**: secret extraction from the PQC handshake (+peer agreement),
  crypto_info packing, TLS_TX/RX install code, fail-closed-no-ULP. [tested]
- **BLOCKED**: throughput improvement [measured] — no TLS ULP in this environment.
- **Residual [design]**: run the A/B throughput on a kTLS host (§5); wire the OOB
  handshake (Phase 1) keys through the same `export_ktls` bridge (already
  compatible — `export_ktls` is on `SessionKeys`, which both handshakes produce).
