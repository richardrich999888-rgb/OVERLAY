#!/usr/bin/env bash
# Seal: stdin = secret; stdout = sealed blob. Uses a PERSISTENT owner primary at
# $SYNTRIASS_TPM_PRIMARY (default 0x81010001) created by tpm_setup.sh. The sealed
# object is bound to this TPM; its seed never leaves. Needs TPM2TOOLS_TCTI.
set -euo pipefail
PRIMARY="${SYNTRIASS_TPM_PRIMARY:-0x81010001}"
W=$(mktemp -d); trap 'rm -rf "$W"' EXIT
cat > "$W/secret.bin"
tpm2_create -C "$PRIMARY" -i "$W/secret.bin" -u "$W/seal.pub" -r "$W/seal.priv" >/dev/null 2>&1
python3 - "$W/seal.pub" "$W/seal.priv" <<'PY'
import sys,struct
pub=open(sys.argv[1],'rb').read(); priv=open(sys.argv[2],'rb').read()
sys.stdout.buffer.write(struct.pack('>I',len(pub))+pub+struct.pack('>I',len(priv))+priv)
PY
