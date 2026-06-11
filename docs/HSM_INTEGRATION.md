# HSM / PKCS#11 Integration

Tags per `KEY_STORAGE_ARCHITECTURE.md`. **No physical HSM was present** —
validation used **SoftHSM2** (the reference software PKCS#11 token). A FIPS HSM is
reached through the *same* PKCS#11 module interface, so SoftHSM2 exercises the real
HSM code path; the physical-HSM acceptance test (§5) is **not** claimed as done.

## 1. Two HSM-backed models (both validated against SoftHSM2)

### A. Wrap-the-seed (at-rest, full hybrid) [implemented]/[measured]

A non-extractable AES-256 key lives in the token; the identity seeds are wrapped
(AES-CBC-PAD) under it. The wrapped blob is on disk; unwrapping happens **in the
token** and requires login (PIN). Protects **both** hybrid seeds.

```
seal:   pkcs11 C_Encrypt(token AES key, seed)  -> IV(16) || ciphertext
unseal: pkcs11 C_Decrypt(token AES key, ct)    -> seed   (in-token)
```

This is the `ExternalKeyProtector` + `CommandSealer` path
(`scripts/keystore/pkcs11_{setup,seal,unseal}.sh`).

### B. Sign-in-HSM (in-use, classical key) [measured (signing)]/[design (wired)]

The classical signing key is generated in the token and **never leaves**; the
token signs. Validated as in-module ECDSA-P256. Wiring it as the identity's
classical signer (instead of the current software hybrid sign) is a protocol-side
change — `[design]`.

**PQC caveat:** PKCS#11/HSMs implement classical algorithms — **not ML-DSA-65**.
So in-HSM signing covers only the classical half; the ML-DSA key stays software-
resident. Wrap-the-seed (model A) protects both seeds at rest. PQC-capable HSMs
(FIPS 204) are emerging — `[future]`.

## 2. Validation evidence — **[measured]** (SoftHSM2)

`scripts/keystore/validate.sh` (captured in `docs/KEY_STORAGE_VALIDATION.txt`):

| Check | Result |
|---|---|
| Token init + non-extractable AES-256 wrapping key | **PASS** |
| In-module ECDSA-P256 sign (private key non-extractable) | **PASS** (64 B signature) |
| AES wrap → unwrap round-trip of a seed | **PASS** |
| Rust `ExternalKeyProtector` (Pkcs11) wraps + transports + unwraps both hybrid seeds, rebuilds the signer | **PASS** (`tests/keystore_external_tests::pkcs11_backed_keystore_seals_and_unlocks_the_signer`) |

Substitute: SoftHSM2 2.6.1 (`libsofthsm2.so`), OpenSC `pkcs11-tool` 0.25.

## 3. Production posture / hardening [design]

- **Native `cryptoki` backend**: replace the `pkcs11-tool` `CommandSealer` with a
  Rust `cryptoki` `TokenSealer` (same trait) for a production-grade adapter
  (session/PIN management, key handles) — `[design]`.
- **Key roles**: separate the wrapping key (AES) from any signing keys; mark all
  `CKA_EXTRACTABLE=false`, `CKA_SENSITIVE=true`.
- **Authentication**: PIN/partition auth; for network HSMs, mutual-TLS to the HSM
  and per-partition policy.
- **AEAD wrap**: prefer AES-GCM (CKM_AES_GCM) over CBC-PAD where the HSM supports
  it (integrity on the wrapped blob); the software keystore already uses AES-GCM.

## 4. Tested vendor mapping (interface only) [design]

| HSM | PKCS#11 module | Notes |
|---|---|---|
| SoftHSM2 (CI/dev) | `libsofthsm2.so` | **validated here** |
| Thales Luna | `libCryptoki2_64.so` | same PKCS#11 calls; partition auth |
| Entrust nCipher | `libcknfast.so` | security-world setup required |
| AWS CloudHSM | `libcloudhsm_pkcs11.so` | network HSM; cluster + cert |
| YubiHSM 2 | `yubihsm_pkcs11.so` | USB; domain/auth-key setup |

Only SoftHSM2 was run here; the others share the PKCS#11 interface and are
`[design]` until validated on the device.

## 5. Physical-HSM acceptance test (REQUIRED before fielding) [design]

1. Install the vendor PKCS#11 module; confirm `pkcs11-tool --module <vendor.so>
   --list-slots` sees the partition.
2. Point `SYNTRIASS_PKCS11_MODULE` at the vendor module; provision PIN + the
   non-extractable wrapping key.
3. Run `scripts/keystore/validate.sh` (PKCS#11 section) / the `pkcs11_backed_*`
   ignored test — expect the same wrap/unwrap + signer-reconstruct PASS.
4. Record the HSM **model and FIPS 140-2/3 certificate level** in the acceptance
   evidence; confirm keys are `CKA_EXTRACTABLE=false`.
5. For in-HSM signing (model B), validate the classical algorithm and wire the
   public key as the identity's classical key.

Required infrastructure: a PKCS#11-capable HSM (or vendor cloud HSM), its module +
credentials, and (for native) the `cryptoki` crate. None present here.

## 6. Reproduce (software substitute)

```
apt-get install -y softhsm2 opensc openssl python3
sudo bash scripts/keystore/validate.sh        # runs the PKCS#11/HSM section against SoftHSM2
```
