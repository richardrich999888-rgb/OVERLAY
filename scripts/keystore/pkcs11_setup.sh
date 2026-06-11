#!/usr/bin/env bash
# Init a SoftHSM2 token (substitute for an HSM) + a non-extractable AES-256
# wrapping key. Env: SOFTHSM2_CONF, SYNTRIASS_PKCS11_MODULE, *_PIN, *_SO_PIN, *_ID.
set -euo pipefail
MOD="${SYNTRIASS_PKCS11_MODULE:?set SYNTRIASS_PKCS11_MODULE}"
PIN="${SYNTRIASS_PKCS11_PIN:-1234}"; SO="${SYNTRIASS_PKCS11_SO_PIN:-3537}"; ID="${SYNTRIASS_PKCS11_ID:-02}"
softhsm2-util --init-token --slot 0 --label syntriass --so-pin "$SO" --pin "$PIN" >/dev/null 2>&1 || true
pkcs11-tool --module "$MOD" --login --pin "$PIN" --keygen --key-type AES:32 --label wrapkey --id "$ID" >/dev/null 2>&1 || true
