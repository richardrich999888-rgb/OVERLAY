# Identity Lifecycle

**Finding:** IL-1 — *no identity lifecycle*. Peer trust was static: public keys
pinned in `/etc/syntriass/identity.toml`, never enrolled, rotated, revoked, or
expired. For a fielded fleet that is unworkable (no way to onboard a node, retire
a key, or respond to a compromise) and it is a hard blocker for any defence
accreditation.

Labels: **[measured]** a test here produced this · **[implemented]** code + test
exists · **[design]** specified, requires external infrastructure (§4).

Scope rule honoured: **only what can be validated here is implemented.** The
software credential system is real and tested; hardware key protection (TPM2 /
PKCS#11 / HSM) is *evaluated* with an honest abstraction + required-infra plan,
not claimed as validated.

---

## 1. What was implemented (`src/identity.rs`)

A minimal, hybrid-PQC credential system built on the **same** Ed25519 + ML-DSA-65
signatures the handshake already uses (no new crypto, no new dependencies). All
lifecycle objects are self-contained, signed byte blobs that verify offline with
only the authority's public keys.

| Lifecycle stage | Mechanism | Status |
|---|---|---|
| **Enrollment** | Node generates a hybrid keypair and an `EnrollmentRequest` carrying its public keys + a **proof-of-possession** (self-signature). The authority verifies PoP before issuing — a node cannot enrol a key it does not control. | **[implemented]** |
| **Issuance** | `IssuingAuthority.issue()` binds `{node_id, serial, epoch, not_before, not_after, pubkeys}` and signs it with the CA's hybrid key → `IdentityCredential`. | **[implemented]** |
| **Rotation** | Issue a new credential with fresh keys + new serial/epoch and an **overlapping** validity window, so trust is never interrupted; the old credential expires on its own. | **[implemented]** |
| **Revocation** | `IssuingAuthority.revoke()` produces a CA-signed `RevocationList` (serials + `next_update` freshness bound). `TrustStore.verify` rejects a credential whose serial is on a valid, fresh CRL. | **[implemented]** |
| **Expiry** | Every credential carries `not_before`/`not_after`; verification fails closed (`NotYetValid` / `Expired`) outside the window. | **[implemented]** |
| **Offline provisioning (air-gap)** | Requests, credentials, and CRLs are opaque signed bytes (`to_bytes`/`from_bytes`). The authority can run fully disconnected; a relying peer needs only the CA public keys (provisioned out-of-band) to verify. No network, no shared state. | **[implemented]** |
| **Renewal** | Re-certify the **same key** with a later window before expiry (continuity of identity), distinct from rotation (new key). | **[implemented]/[tested]** |
| **Recovery** (lost-key / compromised-node) | CA-signed `RecoveryAuthorization` raises a per-node **epoch floor**, immediately superseding all lower-epoch credentials — without waiting for expiry or enumerating serials. | **[implemented]/[tested]** |
| **Emergency rotation** | Same mechanism as recovery used proactively: issue epoch N+1 and a floor=N+1 authorization to cut over immediately (vs. scheduled rotation, which overlaps for zero downtime). | **[implemented]/[tested]** |
| **Revocation propagation** | CRLs carry a strictly-monotonic `crl_number`; `TrustStore.install_crl` rejects a lower-numbered CRL as a **rollback** (an attacker cannot replay an old CRL to un-revoke). | **[implemented]/[tested]** |

See §1A for the recovery/rotation/propagation detail and `OFFLINE_PROVISIONING.md`
for the air-gap distribution model.

### Trust model

- The **relying peer** is provisioned once with the CA's public keys
  (`AuthorityPublic`). From then on it verifies any credential offline:
  CA hybrid-signature → validity window → revocation (if a CRL is supplied).
- Verification yields a `VerifiedIdentity { node_id, epoch, ed25519_pub,
  mldsa65_pub }`, which is **exactly** the peer public-key material the handshake
  pins — closing the loop from lifecycle to enforcement (see §3).
- Every failure is fail-closed (`Err`); no path yields a partially-trusted
  identity. Errors carry no secret material.

### Wire format (deterministic, signature-bound)

```
credential_body = "…credential v1" || node_id(16) || serial(8) || epoch(4)
                  || not_before(8) || not_after(8) || ed25519_pub(32)
                  || len(4)||mldsa65_pub(1952)
credential      = body-fields || ca_ed25519_sig(64) || len(4)||ca_mldsa65_sig(3309)
```

Enrollment requests and revocation lists use the same length-prefixed, domain-
separated scheme. Domain-separation labels (`…credential v1`, `…enrollment-request
v1`, `…revocation-list v1`) prevent cross-protocol signature reuse.

## 1A. Recovery, emergency rotation, renewal, and revocation propagation

### Rotation modes (zero-downtime vs emergency)

- **Scheduled / zero-downtime rotation** [implemented]/[tested]: issue the new
  credential (new key, epoch N+1) with a validity window that **overlaps** the
  old one. Both verify during the overlap, so there is no trust gap; the old
  credential expires on its own. Do *not* raise the epoch floor — both are valid.
  Test: `rotation_gives_uninterrupted_trust_through_a_handshake`.
- **Emergency rotation** [implemented]/[tested]: issue epoch N+1 **and** a
  `RecoveryAuthorization` with `epoch_floor = N+1`. A relying peer that installs
  it rejects the old epoch *immediately* (`Superseded`) — the cut-over is instant,
  not gated on the old credential's expiry. Same machinery as recovery.

### Renewal (same key) [implemented]/[tested]

Before expiry, the node re-requests with the **same** signer; the CA issues a new
credential (same public key, same epoch, later window). The identity is
continuous (same keys), only the validity is extended. Distinct from rotation
(which changes the key). Test: `renewal_extends_validity_with_continuity`.

### Recovery — lost key and compromised node [implemented]/[tested]

A node that **lost** its private key cannot prove possession of the old key. A
**compromised** node's key is in an attacker's hands, so its credential is
cryptographically valid. Both are handled by the same authority-driven flow:

1. The node (or operator) generates a **new** hybrid keypair and enrols it
   normally (proof-of-possession on the *new* key).
2. The CA issues a new credential at **epoch N+1** and a **`RecoveryAuthorization`**
   with `epoch_floor = N+1` (and, for compromise, also a CRL revoking the old
   serial).
3. Relying peers `install_recovery(&authz)` → the old identity is `Superseded`;
   the new one verifies and drives the handshake.

Why the recovery authorization (not just a CRL)? It is **node-scoped and
epoch-based**, so it supersedes the entire prior identity without enumerating
every old serial, works **offline** (one small signed blob), and does not depend
on the old credential's expiry. It is unforgeable without the CA key
(`forged_recovery_authorization_is_rejected`) and node-scoped
(`recovery_floor_is_node_scoped`). Tests:
`recovery_supersedes_lower_epoch_and_admits_new`,
`compromised_node_workflow_revoke_and_supersede`,
`recovered_identity_drives_handshake_old_is_superseded`.

### Revocation propagation (monotonic CRLs) [implemented]/[tested]

Each CRL carries a strictly-increasing `crl_number`. `TrustStore.install_crl`
verifies the CA signature + freshness, then requires `crl_number` to exceed the
last installed — a lower-numbered CRL is rejected as `CrlRollback`. This defeats
an attacker who would replace a CRL revoking a compromised serial with an older
one that omits it. A *newer* CRL that drops a serial legitimately un-revokes it.
Installed CRLs are re-checked for **freshness at every verify** (a CRL gone past
`next_update` ⇒ `StaleRevocationList`, so "not revoked" is never trusted from a
stale list). Tests: `crl_rollback_is_rejected`,
`installed_stale_crl_is_rejected_at_verify_time`.

## 2. Validation evidence — **[measured]**, this run

`cargo test --lib identity` (**21 unit tests**) + `cargo test --test
identity_lifecycle_tests` (**7 integration tests**), all pass:

| Property | Test |
|---|---|
| Enrollment PoP round-trips (incl. wire) | `enrollment_proof_of_possession_round_trips` |
| Forged PoP (swapped key) rejected | `forged_proof_of_possession_is_rejected` |
| Issue → verify happy path | `issue_then_verify_happy_path` |
| Expiry window enforced (NotYetValid/Expired) | `expiry_is_enforced` |
| Tampered credential ⇒ BadSignature | `tampered_credential_fails_ca_signature` |
| Wrong authority rejected | `wrong_authority_is_rejected` |
| Rotation overlap, then old expires | `rotation_overlap_then_old_expires` |
| Revocation blocks a serial; others unaffected | `revocation_blocks_a_credential` |
| Stale CRL rejected (can't trust "not revoked") | `stale_revocation_list_is_rejected` |
| Forged CRL (wrong CA) rejected | `forged_revocation_list_is_rejected` |
| Offline bytes-only round-trip verifies | `offline_provisioning_round_trip` |
| Arbitrary truncations never panic (cred/CRL/authz) | `malformed_blobs_never_panic` |
| **Recovery supersedes lower epoch, admits new** | `recovery_supersedes_lower_epoch_and_admits_new` |
| **Recovery floor is node-scoped** | `recovery_floor_is_node_scoped` |
| **Forged recovery authorization rejected** | `forged_recovery_authorization_is_rejected` |
| **Compromised-node: revoke + supersede** | `compromised_node_workflow_revoke_and_supersede` |
| **CRL rollback rejected; newer un-revokes** | `crl_rollback_is_rejected` |
| **Installed stale CRL rejected at verify** | `installed_stale_crl_is_rejected_at_verify_time` |
| **Renewal extends validity with continuity** | `renewal_extends_validity_with_continuity` |

**End-to-end (lifecycle → real handshake):**

| Property | Test |
|---|---|
| A CA-verified credential's keys drive a real X25519+ML-KEM / Ed25519+ML-DSA handshake to a sealed round-trip | `credential_verified_identity_drives_real_handshake` |
| Expired peer credential ⇒ no trusted keys ⇒ no channel | `expired_peer_credential_blocks_trust_and_handshake` |
| Revoked peer credential ⇒ trust refused | `revoked_peer_credential_blocks_trust` |
| Rotated credential drives a handshake during the overlap | `rotation_gives_uninterrupted_trust_through_a_handshake` |
| **Recovered identity drives a handshake; old superseded** | `recovered_identity_drives_handshake_old_is_superseded` |
| Air-gapped (bytes-only) provisioning round-trip | `air_gapped_bytes_only_provisioning` |
| **Offline recovery distribution (authz + CRL bytes)** | `offline_recovery_distribution_bytes_only` |

The new module is also pure-logic and therefore covered by the project's Miri /
property-test discipline (`docs/FAIL_CLOSED_ASSURANCE.md`): `malformed_blobs_never_panic`
is the in-module fuzz-style robustness check (credential, CRL, and recovery-authz
truncations).

## 2A. Benchmarks — **[measured]** (`cargo bench --bench identity_benchmarks`)

Median of n=200 on this shared sandbox host (CPU-only; **not** target hardware —
numbers localise cost, they are not a fielded claim). ML-DSA-65 signing latency is
intrinsically **variable** (FIPS-204 rejection sampling), so CA-sign operations
show wide spread; verify and PoP are stable.

| Operation | Median latency |
|---|---:|
| Enrollment (hybrid keygen + PoP sign) | ~1 088 µs |
| Proof-of-possession verify | ~324 µs |
| Issue credential (CA hybrid sign) | ~602 µs |
| Verify credential (relying peer) | ~325 µs |
| Issue revocation list (CA hybrid sign) | ~1 824 µs* |
| Authorize recovery (CA hybrid sign) | ~2 089 µs* |

\* the CA-sign spread (issue vs revoke/recovery) reflects ML-DSA rejection-sampling
variance, not algorithmic difference — all are one hybrid sign.

| Artifact | Size |
|---|---:|
| Enrollment request | 5 381 B |
| Identity credential | 5 409 B |
| Revocation list (3 serials) | 3 429 B |
| Recovery authorization | 3 405 B |

Sizes are dominated by the ML-DSA-65 public key (1 952 B) and signature (3 309 B).
These are the bytes a courier carries for air-gap provisioning
(`OFFLINE_PROVISIONING.md`); a credential + recovery-authz + small CRL is well
under 15 KB total — trivially transportable on any offline medium.

## 3. Integration with the handshake

`TrustStore.verify` returns the peer's `ed25519_pub` + `mldsa65_pub`. Those are
the exact inputs `crypto::IdentityMaterial::from_bytes(own_seeds, peer_ed_pub,
peer_mldsa_pub)` expects. So the migration from static pinning to lifecycle trust
is: **replace the `SYNTRIASS_PEER_*_PUB_HEX` config with a verified credential**,
feeding `VerifiedIdentity` into `IdentityMaterial`. The end-to-end test does
exactly this and completes a real handshake — the linkage is proven, not asserted.

> **Boundary [design]:** wiring `resolve_identity()` /
> `read_identity_config_from_sources()` to load a credential file + CRL (instead of
> raw peer-pub hex) and to re-verify on config hot-reload is a config-plumbing
> change, specified here, not yet committed. The credential machinery it would
> call is implemented and tested.

## 4. Hardware key protection — TPM2 / PKCS#11 / HSM (evaluation)

The private-key operation is isolated behind one trait:

```rust
pub trait HybridSigner {
    fn ed25519_public(&self) -> [u8; 32];
    fn mldsa65_public(&self) -> Vec<u8>;
    fn sign_hybrid(&self, msg: &[u8]) -> Result<([u8;64], Vec<u8>), IdentityError>;
}
```

`SoftwareSigner` (keys in zeroizing memory) is the validated reference. A hardware
backend is a drop-in `impl HybridSigner` — **no change to enrollment, issuance,
rotation, revocation, or verification.** None of the hardware backends can be
validated in this sandbox (no TPM device, no PKCS#11 module, no HSM), so per the
scope rule they are **[design]** with the required infrastructure stated.

### The PQC caveat (decisive, stated up front)

TPM 2.0 and the overwhelming majority of fielded HSMs implement **only classical**
asymmetric algorithms (RSA/ECC) — **not ML-DSA**. Therefore a hardware backend can
protect the **Ed25519** half of the hybrid identity in hardware; the **ML-DSA-65**
private key must remain software-protected (zeroizing memory) until PQC-capable
HSMs/TPMs ship. This is acceptable and honest: the hybrid construction means an
attacker must forge **both** signatures, so hardware protection of the classical
key strictly raises the bar even while the PQC key is in software. The
`HybridSigner` trait already permits **split backends** (Ed25519 in the token,
ML-DSA in software).

| Backend | Rust crate | What it protects | Required infrastructure | Status |
|---|---|---|---|---|
| **TPM2** | `tss-esapi` (tpm2-tss) | Ed25519 *(or ECDSA-P256)* signing key sealed in the TPM; never exfiltrable | A TPM 2.0 device (or `swtpm` software TPM for CI), `tpm2-tss` libraries, kernel `/dev/tpmrm0` | **[design]** |
| **PKCS#11** | `cryptoki` | Classical key on a PKCS#11 token (smartcard / SoftHSM / network HSM) | A PKCS#11 `.so` module (e.g. SoftHSM2 for CI, vendor module in prod), token PIN provisioning | **[design]** |
| **HSM** | `cryptoki` (PKCS#11) or vendor SDK | Classical key in a FIPS-140-2/3 HSM; signing in-module | A network/PCIe HSM (Luna, nCipher, CloudHSM) reachable via PKCS#11; partition + auth | **[design]** |
| **PQC-capable HSM** | vendor SDK (emerging) | *Both* Ed25519 and ML-DSA in hardware | An HSM with FIPS-204 support (not yet broadly available) | **[design / future]** |

### Validation strategy for the hardware backends (when infra is available)

1. **CI-grade software emulation first:** `swtpm` (TPM2) and SoftHSM2 (PKCS#11)
   are free, run in a Linux CI lane, and exercise the *exact* `tss-esapi` /
   `cryptoki` code paths. A backend test mirrors the `SoftwareSigner` test set:
   generate/seal a key, run enrollment PoP + credential issuance through the
   hardware-backed signer, verify with the existing `TrustStore`.
2. **Conformance:** assert the public key the token reports equals the key the
   credential binds, and that a sign produced in-token verifies under the
   existing `ed_verify` path (interop with software verification).
3. **Tamper/withdrawal:** pull the token / wrong-PIN ⇒ `sign_hybrid` returns
   `Err` ⇒ enrollment/issuance fails closed (no software-key fallback unless
   explicitly configured).
4. **Hardware acceptance:** repeat (1)–(3) on the real TPM/HSM on the target
   platform; record the device model + FIPS cert in the acceptance evidence.

This sandbox has none of `swtpm`, SoftHSM2, a TPM device, or an HSM, so steps
1–4 are **not** run here. The trait + software backend that those steps plug into
are validated (§2).

## 5. Residual risks

- **R1 — config plumbing not wired (§3 boundary).** The credential machinery is
  tested, but `resolve_identity()` still reads raw peer-pub hex; swapping it to a
  credential+CRL loader is a pending [design] change.
- **R2 — CRL distribution is out of scope.** This module *verifies* a supplied
  CRL; how a fresh CRL reaches an air-gapped node (courier cadence, `next_update`
  sizing) is an operational policy, not code. The freshness check
  (`StaleRevocationList`) enforces that an old CRL is not silently trusted.
- **R3 — no online status (OCSP-style).** Revocation is CRL-pull only, which suits
  air-gap but means revocation latency is bounded by CRL cadence. Acceptable for
  the target environment; documented.
- **R4 — hardware backends unproven here.** TPM2/PKCS#11/HSM are design + plan
  (§4); the PQC key stays in software until PQC-capable HSMs exist.

## 6. Reproduce

```
cargo test --lib identity
cargo test --test identity_lifecycle_tests -- --nocapture
```
