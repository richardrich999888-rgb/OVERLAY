#!/usr/bin/env bash
#
# Sovereign key storage — external-backend validation against SOFTWARE SUBSTITUTES.
#
# Validates the TPM and PKCS#11 key-protection backends of `src/keystore.rs`
# against `swtpm` (software TPM 2.0) and SoftHSM2 (software PKCS#11 token). These
# substitutes exercise the SAME TPM2-ESAPI / PKCS#11 APIs a physical device uses.
# A physical-device acceptance test is still required (docs/{TPM,HSM}_INTEGRATION.md);
# this proves the adapter + abstraction end-to-end.
#
# Requires: swtpm, tpm2-tools, softhsm2, opensc (pkcs11-tool), python3, cargo.
# Run from the repo root:  sudo bash scripts/keystore/validate.sh
set -uo pipefail
HERE="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$HERE"
WORK="$(mktemp -d)"
declare -i RC=0
SWPID=""
trap 'set +e; [ -n "$SWPID" ] && kill "$SWPID" 2>/dev/null; rm -rf "$WORK"' EXIT

echo "================ SOVEREIGN KEY STORAGE — external backend validation ================"
echo "host: $(uname -rm)   date: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo

# ---------- TPM 2.0 (swtpm) ----------
if command -v swtpm >/dev/null && command -v tpm2_createprimary >/dev/null; then
  echo "---- TPM 2.0 backend (swtpm software TPM) ----"
  mkdir -p "$WORK/tpm"
  swtpm socket --tpmstate "dir=$WORK/tpm" --ctrl type=tcp,port=2322 \
        --server type=tcp,port=2321 --tpm2 --flags not-need-init,startup-clear \
        >"$WORK/swtpm.log" 2>&1 &
  SWPID=$!; sleep 1
  export TPM2TOOLS_TCTI="swtpm:host=127.0.0.1,port=2321"
  if scripts/keystore/tpm_setup.sh; then
    # shell-level proof: seal a seed, unseal it, and prove a DIFFERENT TPM cannot.
    printf 'IDENTITY-SEED-EXACTLY-32-BYTES!!' > "$WORK/seed"
    scripts/keystore/tpm_seal.sh < "$WORK/seed" > "$WORK/sealed"
    scripts/keystore/tpm_unseal.sh < "$WORK/sealed" > "$WORK/out"
    if cmp -s "$WORK/seed" "$WORK/out"; then echo "  seal/unseal round-trip ......... PASS (sealed=$(wc -c<"$WORK/sealed")B)"; else echo "  seal/unseal round-trip ......... FAIL"; RC=1; fi
    # Rust adapter end-to-end (ExternalKeyProtector -> CommandSealer -> tpm wrappers).
    SYNTRIASS_TPM_SEAL="$HERE/scripts/keystore/tpm_seal.sh" \
    SYNTRIASS_TPM_UNSEAL="$HERE/scripts/keystore/tpm_unseal.sh" \
      cargo test -q --test keystore_external_tests tpm_backed -- --ignored --nocapture 2>&1 \
      | grep -E "TPM keystore|test result|FAILED" | sed 's/^/  rust: /'
  else echo "  TPM setup FAILED"; RC=1; fi
  kill "$SWPID" 2>/dev/null; SWPID=""
else
  echo "---- TPM 2.0 backend: SKIP (swtpm/tpm2-tools not installed) ----"
fi
echo

# ---------- PKCS#11 / HSM (SoftHSM2) ----------
MOD="$(dpkg -L libsofthsm2 2>/dev/null | grep -m1 'libsofthsm2.so' || true)"
if [ -n "$MOD" ] && command -v pkcs11-tool >/dev/null; then
  echo "---- PKCS#11 / HSM backend (SoftHSM2 software token) ----"
  export SOFTHSM2_CONF="$WORK/softhsm2.conf"
  mkdir -p "$WORK/tokens"
  printf 'directories.tokendir = %s/tokens\nobjectstore.backend = file\nlog.level = ERROR\n' "$WORK" > "$SOFTHSM2_CONF"
  export SYNTRIASS_PKCS11_MODULE="$MOD"
  scripts/keystore/pkcs11_setup.sh
  # in-module signing proof (private key non-extractable).
  pkcs11-tool --module "$MOD" --login --pin 1234 --keypairgen --key-type EC:prime256v1 --label idkey --id 01 >/dev/null 2>&1 || true
  printf 'syntriass' | openssl dgst -sha256 -binary > "$WORK/h"
  if pkcs11-tool --module "$MOD" --login --pin 1234 --sign --mechanism ECDSA --id 01 --input-file "$WORK/h" --output-file "$WORK/sig" >/dev/null 2>&1; then
    echo "  in-module ECDSA sign ........... PASS (sig=$(wc -c<"$WORK/sig")B, key non-extractable)"
  else echo "  in-module ECDSA sign ........... FAIL"; RC=1; fi
  # Rust adapter end-to-end (wrap the hybrid seeds under the token AES key).
  SYNTRIASS_PKCS11_SEAL="$HERE/scripts/keystore/pkcs11_seal.sh" \
  SYNTRIASS_PKCS11_UNSEAL="$HERE/scripts/keystore/pkcs11_unseal.sh" \
    cargo test -q --test keystore_external_tests pkcs11_backed -- --ignored --nocapture 2>&1 \
    | grep -E "Pkcs11 keystore|test result|FAILED" | sed 's/^/  rust: /'
else
  echo "---- PKCS#11 backend: SKIP (SoftHSM2/opensc not installed) ----"
fi
echo

[ "$RC" -eq 0 ] && echo "RESULT: PASS — external key-storage backends validated against software substitutes." \
               || echo "RESULT: FAIL — see rows above."
exit "$RC"
