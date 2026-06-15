# Air-Gap Trust Model

**Internal Security Hardening and Pre-Audit Remediation.**

## Trust roots
- **Issuing signer(s)**: hold the hybrid Ed25519+ML-DSA private keys that sign
  bundles. Kept offline (ideally TPM/HSM-sealed via the existing keystore layer).
- **Trust anchors**: each node is provisioned out-of-band with the signer's
  **public** keys (a `TrustStore` anchor), pinned by `signer-id =
  SHA256(domain || ed_pub || ml_pub)`. This pinning is the security root — it must
  be delivered by a trusted channel at node bring-up (e.g. burned into the install
  image, or hand-carried and fingerprint-confirmed).

## Object lifecycle
1. **Sign** (offline, on the issuing host): `SignedBundle::sign(kind, signer,
   version, payload)`; `version` strictly increases per `(kind, signer)`.
2. **Transport** (removable media): `to_bytes()` → file. The file is
   self-describing but **not** self-authenticating-by-hash; only the signature
   gates it.
3. **Verify + apply** (on the target, offline): `from_bytes()` → `TrustStore::
   accept()`. Fail-closed on revoked/unknown/replay/corrupt/invalid.

## Threats and controls
| Threat | Control |
|---|---|
| Edit artifact in transit | hybrid signature over canonical message |
| Substitute signer's identity (MITM) | only pinned anchors trusted; unknown signer rejected |
| Re-sign with attacker key | unknown signer rejected |
| Replay an old (e.g. vulnerable) bundle | monotonic version floor per (kind, signer) |
| Cross-use a policy sig as an identity export | domain separation by `BundleKind` |
| Corrupted media | structural parse + hash + signature, all fail closed |
| Signer key compromise | revoke the signer-id (`TrustStore::revoke`); rotate to a new anchor |

## Revocation & rotation (operational, [design])
- Revocation is currently node-local (`revoke(signer_id)`). A **signed revocation
  list** (itself a `BundleKind` with a monotonic version) distributed offline is
  the production mechanism — reuses the same signing core; not yet built.
- Anchor rotation: distribute a new anchor out-of-band; sign a transition bundle
  with the old key authorizing the new (chain of trust). `[design]`.

## Residual risks
- The **anchor distribution channel** at bring-up is the trust root; if that is
  compromised, all downstream signing is moot. This is inherent to any PKI and
  must be an accredited procedure.
- A compromised **issuing key** can sign malicious bundles until revoked; keep it
  offline/hardware-sealed and minimise its online exposure.
