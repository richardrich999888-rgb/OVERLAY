# CR-3 — Air-Gapped Integrity Protection: Signed Bundles

**Internal Security Hardening and Pre-Audit Remediation.** Not a certification.

## Finding (recap)
Offline artifacts (identity exports, policy bundles) were protected only by an
**unkeyed SHA-256 stored inside the artifact**. An active adversary on the
sneakernet path edits the artifact, recomputes the hash, and passes the check —
and via peer-key substitution in an identity export, MITMs the entire overlay's
authentication. The "fail-closed on tampered artifact" claim was false against an
active adversary.

## Remediation — [implemented] [tested] (`src/airgap.rs`)
Hybrid **Ed25519 + ML-DSA-65** signature over a canonical, domain-separated,
length-delimited message binding `{domain, kind, signer-id, monotonic version,
payload}`. Verification is against a **pre-distributed trust anchor**
(`TrustStore`). The payload SHA-256 is retained for accidental-corruption
detection only — it is **never** the security gate.

### Fail-closed decision order (`TrustStore::verify`)
1. **Revoked signer** → `RevokedSigner`.
2. **Unknown signer** (not a pinned anchor) → `UnknownSigner`.
3. **Replay** (`version <= floor` for this `(kind, signer)`) → `ReplayedBundle`.
4. **Corrupted payload** (carried hash ≠ payload) → `CorruptedPayload`.
5. **Hybrid signature** over the canonical message (BOTH Ed25519 and ML-DSA must
   verify) → else `InvalidSignature`.
`accept()` additionally advances the replay floor so a bundle cannot be replayed
after application.

### On-disk format
`to_bytes`/`from_bytes` produce/parse a length-delimited file (magic `SYNTABG1`)
that travels on removable media; structural problems (bad magic, truncation,
trailing bytes) fail closed before any signature check.

## Validation
- `src/airgap.rs` unit (8): valid, tampered payload, signer substitution,
  signer-id forgery, replay, corrupted media, revoked signer, kind confusion.
- `tests/cr3_airgap_signing_tests.rs` (6): on-disk roundtrip, on-disk tamper,
  **peer-key-substitution MITM blocked**, replay of old bundle, revoked signer,
  truncated media. All pass.

Required scenarios → result: **bundle tampering** rejected; **signer substitution**
rejected (unknown signer); **replay** rejected (version floor); **corrupted media**
rejected (hash/signature/structure); **revoked signer** rejected.

## Status & residual
CR-3 **cryptographic core: Closed `[implemented] [tested]`**.
- `[design]` — deployment wiring: `deploy/airgap.sh` / `import-peer` /
  `apply-policy-bundle` must call this verifier instead of the SHA-256 check, and
  a trust-anchor + signing-key distribution/rotation workflow must be operated
  (see `docs/AIRGAP_TRUST_MODEL.md`). Until the shell is rewired, the deployment
  path still uses the old check; the secure mechanism exists and is tested but is
  not yet the default on the wire.
