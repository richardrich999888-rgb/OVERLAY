#!/usr/bin/env bash
# Shared paths + helpers for the SYNTRIASS Overlay deployment scripts.
# All paths are overridable via environment for packaging/testing (DESTDIR,
# PREFIX, SYSCONFDIR, UNITDIR, STATEDIR, BACKUPDIR).
set -euo pipefail

PREFIX="${PREFIX:-/usr/local}"
SYSCONFDIR="${SYSCONFDIR:-/etc/syntriass}"
UNITDIR="${UNITDIR:-/etc/systemd/system}"
STATEDIR="${STATEDIR:-/var/lib/syntriass}"
BACKUPDIR="${BACKUPDIR:-/var/lib/syntriass/backups}"
DOCDIR="${DOCDIR:-$PREFIX/share/doc/syntriass}"
DESTDIR="${DESTDIR:-}"            # staging prefix for packaging/tests
SVC_USER="${SVC_USER:-syntriass}"
SERVICE="syntriass-overlay.service"

# The three binaries, installed names <- cargo bin name.
BIN_DAEMON="syntriass-daemon"     # <- target/release/daemon
BIN_IDENTITY="syntriass-identity" # <- target/release/syntriass-identity
BIN_WEBHOOK="syntriass-webhook"   # <- target/release/webhook
VALIDATE_BIN="syntriass-overlay-validate-config"
INSTALL_BIN="syntriass-overlay-install"

# Hex lengths (characters) the daemon's identity contract requires.
LEN_ED25519_SEED=64
LEN_MLDSA65_SEED=64
LEN_PEER_ED25519=64
LEN_PEER_MLDSA65=3904

log()  { printf '[syntriass] %s\n' "$*"; }
warn() { printf '[syntriass] WARN: %s\n' "$*" >&2; }
die()  { printf '[syntriass] FATAL: %s\n' "$*" >&2; exit 1; }

# d <path> = DESTDIR-prefixed path
d() { printf '%s%s' "$DESTDIR" "$1"; }

have_systemd() { [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; }

# Extract a `key = "value"` value from a simple toml file. Handles a quoted value
# with an optional trailing `# comment`, or a bare unquoted value. Echoes the
# value (possibly empty).
toml_get() {
  local file="$1" key="$2" rhs
  [ -f "$file" ] || { echo ""; return 0; }
  rhs="$(sed -n "s/^[[:space:]]*${key}[[:space:]]*=[[:space:]]*//p" "$file" | head -1)"
  case "$rhs" in
    \"*) printf '%s' "${rhs#\"}" | sed 's/".*$//' ;;   # between the first quotes
    *)   printf '%s' "$rhs" | sed 's/[[:space:]]*#.*$//; s/[[:space:]]*$//' ;;  # bare, strip comment
  esac
}

# True if $1 is exactly $2 lowercase-hex characters.
is_hex_len() {
  local v="$1" n="$2"
  [ "${#v}" -eq "$n" ] && printf '%s' "$v" | grep -qiE '^[0-9a-f]+$'
}
