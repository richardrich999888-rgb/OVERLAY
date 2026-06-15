#!/usr/bin/env bash
# Unseal: stdin = IV(16) || ciphertext; stdout = secret (decrypted in-token).
set -euo pipefail
MOD="${SYNTRIASS_PKCS11_MODULE:?}"; PIN="${SYNTRIASS_PKCS11_PIN:-1234}"; ID="${SYNTRIASS_PKCS11_ID:-02}"
W=$(mktemp -d); trap 'rm -rf "$W"' EXIT
cat > "$W/in.bin"
head -c16 "$W/in.bin" > "$W/iv.bin"
tail -c +17 "$W/in.bin" > "$W/c.bin"
IVHEX=$(od -An -tx1 "$W/iv.bin" | tr -d ' \n')
pkcs11-tool --module "$MOD" --login --pin "$PIN" --id "$ID" --decrypt \
  --mechanism AES-CBC-PAD --iv "$IVHEX" --input-file "$W/c.bin" --output-file "$W/d.bin" >/dev/null 2>&1
cat "$W/d.bin"
