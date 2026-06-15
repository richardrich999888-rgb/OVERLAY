# TPM 2.0 Integration

Tags per `KEY_STORAGE_ARCHITECTURE.md`. **No physical TPM was present in this
environment** — validation used `swtpm` (the reference software TPM 2.0). What was
exercised is the real TPM2 command/ESAPI path; the physical-device acceptance test
is specified in §5 and is **not** claimed as done.

## 1. Model: seal the seed to the TPM [implemented]/[measured]

The long-term identity seeds are **sealed** to the TPM under the owner-hierarchy
primary key. The sealing object can be unsealed **only by the same TPM** (the
primary's seed never leaves the chip), so the seeds on disk are useless off the
authorized platform.

```
seal:   tpm2_create -C <persistent owner primary> -i <seed>  ->  (pub, priv)
        sealed blob = len(pub)||pub||len(priv)||priv          (stored on disk)
unseal: tpm2_load -C <primary> -u pub -r priv ; tpm2_unseal   ->  <seed>
```

This is the `ExternalKeyProtector` + `CommandSealer` path
(`scripts/keystore/tpm_{setup,seal,unseal}.sh`); the Rust adapter pipes the seed
to `tpm_seal.sh` and reads the seed back from `tpm_unseal.sh`.

## 2. Why seal-the-seed (not sign-in-TPM) for the hybrid

TPM 2.0 supports RSA/ECC (ECDSA-P256) — **not ML-DSA-65**. So an in-TPM signer
could protect only the classical half. **Sealing** protects **both** hybrid seeds
at rest with one mechanism, and keeps the audited software signing path. (An
ECDSA-P256-in-TPM classical signer is an option once the protocol accepts P-256
as the classical algorithm — `[design]`.)

## 3. Validation evidence — **[measured]** (swtpm)

`scripts/keystore/validate.sh` (captured in `docs/KEY_STORAGE_VALIDATION.txt`):

| Check | Result |
|---|---|
| Seal a 32-byte seed → sealed object | **216 B blob** |
| Unseal on the same TPM | **round-trip MATCH** |
| Unseal on a **different** TPM | **FAILS** (sealed-to-hardware confirmed) |
| Rust `ExternalKeyProtector` (Tpm2) seals + transports + unseals both hybrid seeds, rebuilds the signer | **PASS** (`tests/keystore_external_tests::tpm_backed_keystore_seals_and_unlocks_the_signer`) |

Substitute: `swtpm` 0.7.3 + `tpm2-tools` 5.6, TCTI `swtpm:host=127.0.0.1,port=2321`.

## 4. Production posture / hardening [design]

- **PCR-policy sealing**: seal under a policy bound to platform PCRs (measured
  boot), so the seed unseals only in a known-good firmware/kernel state — not just
  "this TPM". The wrapper uses the owner primary today; a `tpm2_policypcr` variant
  is the hardened form.
- **Auth value / DA lockout**: protect the sealing object with an auth value and
  rely on the TPM's dictionary-attack lockout.
- **Native ESAPI backend**: replace the `tpm2`-tools `CommandSealer` with a Rust
  `tss-esapi` `TokenSealer` (same trait) to drop the shell-out — `[design]`.

## 5. Physical-device acceptance test (REQUIRED before fielding) [design]

On the target platform with a real TPM 2.0:

1. Confirm `/dev/tpmrm0` and `tpm2-tools` talk to the chip (`tpm2_getcap properties-fixed`).
2. Point the wrappers at the hardware TCTI (`TPM2TOOLS_TCTI=device:/dev/tpmrm0`).
3. Run `scripts/keystore/validate.sh` (or the `tpm_backed_*` ignored test) — expect
   the same round-trip PASS + cross-device-FAIL behaviour as the swtpm run.
4. Record the TPM **manufacturer, firmware version, and any FIPS/CC certification**
   in the acceptance evidence.
5. Validate **power-cycle persistence** (the persistent primary survives reboot)
   and **PCR-policy** unseal-only-in-known-state if used.

Required infrastructure: a TPM-2.0-equipped target board, `tpm2-tss`/`tpm2-tools`
on the image, and (for native) the `tss-esapi` crate. None present here.

## 6. Reproduce (software substitute)

```
apt-get install -y swtpm swtpm-tools tpm2-tools python3
sudo bash scripts/keystore/validate.sh        # runs the TPM section against swtpm
```
