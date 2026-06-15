# CR-4 — Supply Chain Protection: Signed Packages

**Internal Security Hardening and Pre-Audit Remediation.** Not a certification.

## Finding (recap)
`deploy/package.sh` shipped a `SHA256SUMS` *inside* the package; `deploy/install.sh`
never verified it and installed/ran binaries as **root**. Anyone who could modify
the distributed tarball achieved root code execution on every installing host.

## Remediation — [implemented] [tested]
A package is a set of files plus a **signed manifest** (`path → sha256`). The
manifest is a `SignedBundle` of `BundleKind::Package` (same hybrid Ed25519+ML-DSA
core as CR-3, `src/airgap.rs`). The installer gate (modelled and tested in
`tests/cr4_supply_chain_tests.rs::install_check`) does, **before executing
anything**:
1. `TrustStore::verify(manifest)` — authenticate the manifest (signer, signature,
   replay floor); fail closed on unknown/revoked/replayed/invalid.
2. Recompute each delivered file's SHA-256 and require it to equal the signed
   manifest entry; any mismatch ⇒ reject (no execution).

So: **no unsigned package executes** (manifest signature required), **no modified
package executes** (file-hash mismatch), **no rollback/replayed package executes**
(version floor), **no forged package executes** (unknown signer).

## Validation — `tests/cr4_supply_chain_tests.rs` (6, all pass)
| Scenario | Result |
|---|---|
| legitimate package | installs |
| modified package (swap a binary post-sign) | rejected (hash mismatch) |
| forged package (attacker re-signs) | rejected (unknown signer) |
| replayed/rollback package | rejected (version floor) |
| revoked signing key | rejected |
| compromised-repository simulation | rejected (unknown signer; on-disk round-trip) |

## Trust-root management
Same model as `docs/AIRGAP_TRUST_MODEL.md`: an offline (TPM/HSM-sealed) issuing
signer; nodes pinned to the signer's public anchor at bring-up; revocation by
signer-id. See `docs/PACKAGE_SIGNING_ARCHITECTURE.md`.

## Status & residual
CR-4 **cryptographic core: Closed `[implemented] [tested]`**.
- `[design]` — deployment wiring: `deploy/package.sh` must emit a signed manifest
  and `deploy/install.sh` must run the `install_check` gate (verify + per-file
  hash) before `install -m 0755` / execution. Until then, `install.sh` still does
  no integrity verification; the secure mechanism exists and is tested but is not
  yet enforced by the shipped installer.
