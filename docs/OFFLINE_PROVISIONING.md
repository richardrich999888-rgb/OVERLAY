# Offline Provisioning (Air-Gap)

Tags: **[implemented]** code exists · **[tested]** automated test passes ·
**[measured]** a number was produced here · **[design]** specified, needs external
infra. Companion to `IDENTITY_LIFECYCLE.md`.

SYNTRIASS identity is **cloud-free by construction**: every lifecycle artifact is
a self-contained, CA-signed byte blob that a relying peer verifies using only the
CA's public keys. No online CA, no OCSP responder, no directory service, no
network at verification time. This document specifies the air-gapped trust
bootstrap and the offline distribution of credentials, revocations, and recovery
authorizations.

## 1. Why it is offline-native [implemented]

| Property | Consequence for air-gap |
|---|---|
| Credentials/CRLs/recovery-authz are signed bytes (`to_bytes`/`from_bytes`) | Carried on any medium (USB, optical, data-diode); verified with no network. |
| Verification needs only `AuthorityPublic` (2 public keys) | The relying peer holds a tiny, static trust anchor — provisioned once. |
| CRLs are freshness-bounded (`next_update`) + monotonically numbered (`crl_number`) | An old CRL cannot be replayed to un-revoke; staleness is detected even offline. |
| Recovery uses a per-node **epoch floor**, not online status | Compromise/loss is handled by one signed blob, no live revocation service. |
| No timestamps from the network | Time is supplied by the verifying host's clock (`now`), assumed monotonic. |

## 2. Trust bootstrap (offline) [implemented]/[tested]

The single root of trust a node must receive out-of-band is the **CA public key
pair** (`AuthorityPublic`: 32-byte Ed25519 + 1 952-byte ML-DSA-65). Everything
else flows from credentials it verifies against that anchor.

```
 [ Offline Issuing Authority ]            [ field node / relying peer ]
   holds CA hybrid signing key       ──provision once, out-of-band──►  CA public keys
   (never leaves the air-gapped CA)      (e.g. burned at depot / on a
                                          tamper-evident token)
```

Bootstrap integrity is an **operational** control: the CA public keys must be
delivered with out-of-band integrity (sealed media, dual-control, a printed
fingerprint checked at the depot). This is a procedure, not code — **[design]**
for the SOP; the verification that *uses* the anchor is **[tested]**.

## 3. Enrollment, offline [implemented]/[tested]

```
 node                         courier            offline CA
 ----                         -------            ----------
 generate hybrid keypair
 EnrollmentRequest.to_bytes() ──USB──►  from_bytes(); verify proof-of-possession
                                        issue(...).to_bytes()
                              ◄──USB──  (IdentityCredential bytes)
 install credential
```

The request carries the node's public keys + a self-signature
(proof-of-possession), so the CA can confirm the node controls the keys it is
certifying — **without any interactive protocol**. Test:
`air_gapped_bytes_only_provisioning` (round-trips request → credential through
`to_bytes`/`from_bytes` and verifies with the CA public keys only).

## 4. Offline revocation distribution [implemented]/[tested]

The CA publishes a numbered `RevocationList` on a cadence. Couriers carry the
latest CRL to each enclave; the relying peer `install_crl(crl, now)`:

- verifies the CA signature and that `now < next_update` (freshness);
- requires `crl_number` strictly greater than the last installed — a stale/older
  CRL is rejected as `CrlRollback` (an adversary cannot "un-revoke" by replaying
  an old list);
- a *newer* CRL that legitimately drops a serial un-revokes it.

Operational parameters (**[design]** — set per deployment):

| Parameter | Meaning | Guidance |
|---|---|---|
| CRL cadence | How often the CA cuts a new CRL | ≤ courier round-trip so a fresh CRL is always in-window |
| `next_update` horizon | When a CRL becomes stale | ≥ cadence + worst-case courier latency; too long widens the revocation window, too short risks false `StaleRevocationList` |
| `crl_number` | Monotonic counter | One global sequence per CA |

Test: `crl_rollback_is_rejected`, `installed_stale_crl_is_rejected_at_verify_time`,
`offline_recovery_distribution_bytes_only`.

## 5. Offline recovery / compromise response [implemented]/[tested]

A lost-key or compromised-node event is resolved with **two small signed blobs**,
both courier-distributable:

1. a **`RecoveryAuthorization`** (raises the node's epoch floor → supersedes the
   old identity immediately), and
2. for compromise, a **CRL** revoking the old serial.

The relying peer installs both offline; the old credential is then rejected
(`Superseded` and/or `Revoked`) and the node's new credential drives the
handshake. Test: `offline_recovery_distribution_bytes_only`,
`recovered_identity_drives_handshake_old_is_superseded`.

## 6. Courier payload sizes [measured]

From `cargo bench --bench identity_benchmarks` (bytes):

| Artifact | Size |
|---|---:|
| Enrollment request | 5 381 B |
| Identity credential | 5 409 B |
| Recovery authorization | 3 405 B |
| Revocation list (3 serials) | 3 429 B (+8 B per extra serial) |

A complete provisioning bundle (credential + recovery authz + a small CRL) is
**< 15 KB** — fits on any offline medium with room for thousands of revoked
serials. Sizes are dominated by ML-DSA-65 (1 952 B key, 3 309 B signature); they
are the unavoidable cost of post-quantum signatures and are still trivially
transportable.

## 7. Data-diode / one-way considerations [design]

For one-way (data-diode) enclaves where the node cannot send a request back to the
CA:

- **Pre-provisioning**: the CA pre-issues credentials for known node IDs and pushes
  them one-way with the CRL/authz stream. Proof-of-possession is then validated at
  depot key-generation time (the node's keypair is generated under CA witness), not
  over the diode.
- **Inbound-only updates**: CRLs and recovery authorizations are one-way pushes —
  they need no acknowledgement, so they suit a diode natively.

This is **[design]** (an operational topology); the artifacts it moves are the same
`[tested]` signed blobs.

## 8. What is NOT provided here (honest boundary)

- **Out-of-band anchor integrity** (delivering the CA public keys) is an SOP,
  not code — **[design]**.
- **Hardware-rooted CA key** (the CA's own signing key in an HSM) is the
  `HybridSigner` hardware backend — **[design]** (see `IDENTITY_LIFECYCLE.md §4`).
- **Time source**: verification trusts the host clock; a defeated clock widens
  expiry/freshness windows. A trusted/monotonic time source is an operational
  assumption — **[design]**.
- **Courier cadence vs revocation latency** is a deployment policy, not enforced
  by code (the freshness check bounds the damage). — **[design]**

## 9. Reproduce

```
cargo test --test identity_lifecycle_tests -- --nocapture   # offline + recovery paths
cargo bench --bench identity_benchmarks                      # courier payload sizes
```
