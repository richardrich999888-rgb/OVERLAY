# Key Storage Architecture

Tags: **[implemented]** code exists · **[tested]** automated test passes here ·
**[measured]** a real run produced this · **[design]** specified, needs external
infra. Companion docs: `TPM_INTEGRATION.md`, `HSM_INTEGRATION.md`.

**Mission:** replace the "raw key seeds in a file / env var" assumption with a
defence-grade, backend-agnostic key-protection layer, and validate every backend
that can be validated in this environment — **without claiming hardware validation
that did not happen.**

## 1. The abstraction (`src/keystore.rs`) [implemented]/[tested]

```
                       ┌────────────────────────────────────────┐
  identity seeds  ───► │  KeyProtector (trait): seal / unseal     │ ◄── label-bound
  (Ed25519, ML-DSA)    │    backend() -> Software|Tpm2|Pkcs11|Hsm │     AEAD/AAD
                       └───────────────┬───────────────┬─────────┘
                                       │               │
                ┌──────────────────────┘               └───────────────────────┐
        SoftwareKeyProtector                          ExternalKeyProtector<T>
        AES-256-GCM under a passphrase KEK            T: TokenSealer
        (no-hardware / dev path)                      └── CommandSealer ──► tpm2 / pkcs11
                                                                            vendor tooling
```

- **`KeyProtector`** — `seal(label, secret)` / `unseal(label, sealed)`. The
  `label` is bound as AEAD associated data (or backend object id), so a blob for
  one purpose can't be substituted for another. [implemented]
- **`SealedKeystore`** — bundles the *sealed* Ed25519 + ML-DSA-65 seeds + node id
  into one self-contained, air-gap-transportable blob (`to_bytes`/`from_bytes`).
  `unlock_signer()` unseals transiently and rebuilds the audited
  `identity::SoftwareSigner`. The raw seeds touch memory only during unlock and are
  zeroized after. [implemented]/[tested]
- The signing path is unchanged — protection is purely *at rest*; the existing
  PQC handshake/identity code consumes the unlocked signer exactly as before.

## 2. Backends supported

| Backend | Model | Status | Validation |
|---|---|---|---|
| **Software** | AES-256-GCM seal under a passphrase-derived KEK | **[implemented]/[tested]** | 10 unit tests (round-trip, wrong-pass, wrong-label, tamper, malformed, keystore reconstruct) |
| **TPM 2.0** | Seed sealed to the TPM (owner-hierarchy primary); openable only by that TPM | **[implemented]; [measured] vs swtpm** | `scripts/keystore/validate.sh` + `tests/keystore_external_tests.rs` |
| **PKCS#11** | Seed wrapped under a non-extractable token AES key; (also: in-module signing) | **[implemented]; [measured] vs SoftHSM2** | same harness |
| **HSM** | PKCS#11 to a FIPS HSM (same code path as PKCS#11) | **[implemented adapter]; [design] for a real HSM** | SoftHSM2 proves the PKCS#11 path; physical HSM = acceptance test |

## 3. Two protection models (both supported)

1. **Seal-the-seed (at-rest protection).** The long-term seed is encrypted under a
   key the backend holds; it is decrypted only with the backend present. Works
   uniformly for the **full hybrid** (both Ed25519 and ML-DSA seeds). This is the
   `KeyProtector`/`TokenSealer` abstraction. **[implemented]/[tested]/[measured]**
   (TPM seal, PKCS#11 wrap).
2. **Sign-in-token (in-use protection).** The classical signing key is generated
   in and never leaves the token; the token signs. Strongest, but the token must
   support the algorithm. Validated as in-module ECDSA on SoftHSM2; integrating it
   as the identity's classical signer (vs. the current software hybrid sign) is a
   protocol-side change. **[measured] (signing); [design] (wired as the identity signer)**.

**PQC caveat (decisive, stated up front):** TPM 2.0 and most fielded HSMs implement
**only classical** algorithms (RSA/ECC) — **not ML-DSA**. So *sign-in-token* can
protect only the classical key; *seal-the-seed* protects **both** seeds at rest
(the model this layer uses by default). The ML-DSA key stays software-resident
during signing until PQC-capable HSMs ship. The hybrid still requires forging both.

## 4. Validation evidence — **[measured]** (`docs/KEY_STORAGE_VALIDATION.txt`)

`sudo bash scripts/keystore/validate.sh` on kernel 6.18, swtpm + SoftHSM2:

| Backend | Check | Result |
|---|---|---|
| Software | 10 unit tests (`cargo test --lib keystore`) | **PASS** |
| TPM 2.0 (swtpm) | seal a 32-byte seed → sealed 216 B → unseal | **round-trip PASS** |
| TPM 2.0 (swtpm) | a **different** TPM cannot unseal the blob | **PASS** (sealed-to-hardware) |
| TPM 2.0 (swtpm) | Rust `ExternalKeyProtector` → tpm wrappers: seal+transport+unseal both hybrid seeds, signer reconstructed | **PASS** |
| PKCS#11 (SoftHSM2) | in-module ECDSA sign (private key non-extractable) | **PASS** (64 B sig) |
| PKCS#11 (SoftHSM2) | Rust adapter wraps both hybrid seeds under the token key, unseals, signer reconstructed | **PASS** |

`swtpm` and SoftHSM2 are the **standard software substitutes** that exercise the
**same** TPM2-ESAPI / PKCS#11 APIs a physical device uses. **This is not a claim of
physical-hardware validation** — that acceptance test is documented per device in
`TPM_INTEGRATION.md` / `HSM_INTEGRATION.md`.

## 5. Air-gapped operation & offline provisioning [implemented]/[tested]

- A `SealedKeystore` is self-contained signed/sealed bytes — provisionable on any
  offline medium and unlocked on the target with its backend present.
- The software backend needs only a passphrase (no network); the TPM/PKCS#11
  backends need only the local device (no network). No cloud dependency anywhere.
- Ties into `OFFLINE_PROVISIONING.md`: the keystore is *how* a node's seeds arrive
  and live on the box; the identity credential is *how* its public keys are trusted.

## 6. Residual risks

- **R1 [design]** Physical-device acceptance (a real TPM chip / FIPS HSM) is not
  done here; only software substitutes. Per-device steps in `TPM/HSM_INTEGRATION.md`.
- **R2 [design]** The software backend's passphrase KEK uses HKDF (not a memory-hard
  KDF). For low-entropy passphrases, use argon2id or — preferably — a hardware KEK.
- **R3 [design]** ML-DSA key is software-resident during signing (no PQC HSM).
- **R4 [implemented/accepted]** The `CommandSealer` shells out to vendor tooling;
  a native `tss-esapi`/`cryptoki` Rust backend is a cleaner production form (same
  `TokenSealer` trait), deferred to keep the main crate dependency-free.
- **R5 [design]** TPM sealing here is to the owner primary (platform binding); PCR
  policy sealing (bind to a measured boot state) is a stronger, documented option.

## 7. Reproduce

```
cargo test --lib keystore                       # software backend + abstraction
sudo bash scripts/keystore/validate.sh          # TPM (swtpm) + PKCS#11 (SoftHSM2)
```
