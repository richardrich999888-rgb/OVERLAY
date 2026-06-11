#!/usr/bin/env bash
# Seal: stdin=secret; stdout = IV(16) || AES-CBC-PAD ciphertext. The AES key lives
# in the PKCS#11 token (non-extractable); the seed never leaves in clear.
set -euo pipefail
MOD="${SYNTRIASS_PKCS11_MODULE:?}"; PIN="${SYNTRIASS_PKCS11_PIN:-1234}"; ID="${SYNTRIASS_PKCS11_ID:-02}"
W=$(mktemp -d); trap 'rm -rf "$W"' EXIT
cat > "$W/p.bin"
head -c16 /dev/urandom > "$W/iv.bin"
IVHEX=$(od -An -tx1 "$W/iv.bin" | tr -d ' \n')
pkcs11-tool --module "$MOD" --login --pin "$PIN" --id "$ID" --encrypt \
  --mechanism AES-CBC-PAD --iv "$IVHEX" --input-file "$W/p.bin" --output-file "$W/c.bin" >/dev/null 2>&1
cat "$W/iv.bin" "$W/c.bin"
