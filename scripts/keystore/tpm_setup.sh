#!/usr/bin/env bash
# Create the persistent owner primary at $SYNTRIASS_TPM_PRIMARY (idempotent).
set -euo pipefail
PRIMARY="${SYNTRIASS_TPM_PRIMARY:-0x81010001}"
W=$(mktemp -d); trap 'rm -rf "$W"' EXIT
if tpm2_readpublic -c "$PRIMARY" >/dev/null 2>&1; then exit 0; fi
tpm2_createprimary -C o -g sha256 -G ecc -c "$W/p.ctx" >/dev/null 2>&1
tpm2_evictcontrol -C o -c "$W/p.ctx" "$PRIMARY" >/dev/null 2>&1
tpm2_flushcontext -t >/dev/null 2>&1 || true
