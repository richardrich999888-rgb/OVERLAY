#!/usr/bin/env bash
# Unseal: stdin = sealed blob; stdout = secret. Uses the persistent primary.
set -euo pipefail
PRIMARY="${SYNTRIASS_TPM_PRIMARY:-0x81010001}"
W=$(mktemp -d); trap 'rm -rf "$W"' EXIT
cat > "$W/blob.bin"
python3 - "$W/blob.bin" "$W/seal.pub" "$W/seal.priv" <<'PY'
import sys,struct
b=open(sys.argv[1],'rb').read(); o=0
(n,)=struct.unpack_from('>I',b,o); o+=4; open(sys.argv[2],'wb').write(b[o:o+n]); o+=n
(n,)=struct.unpack_from('>I',b,o); o+=4; open(sys.argv[3],'wb').write(b[o:o+n]); o+=n
PY
tpm2_load -C "$PRIMARY" -u "$W/seal.pub" -r "$W/seal.priv" -c "$W/seal.ctx" >/dev/null 2>&1
secret=$(tpm2_unseal -c "$W/seal.ctx")
printf '%s' "$secret"
tpm2_flushcontext -t >/dev/null 2>&1 || true
