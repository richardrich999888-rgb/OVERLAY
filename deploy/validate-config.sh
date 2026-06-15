#!/usr/bin/env bash
# Validate a SYNTRIASS Overlay configuration BEFORE the daemon starts.
# Installed as $PREFIX/bin/syntriass-overlay-validate-config and invoked by the
# systemd unit's ExecStartPre. Fail-closed: any problem exits non-zero so the
# service does NOT start with a broken/weak/missing identity.
#
# Checks (matching the daemon's own contract, src/crypto/mod.rs):
#   * policy.toml suite is nist768 | nist1024 (or SYNTRIASS_SUITE set)
#   * identity present either via env vars OR /etc/syntriass/identity.toml
#   * all four identity hex fields are present and correctly sized
#   * identity.toml is not world-readable (secret hygiene)
HERE="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=lib.sh
if [ -f "$HERE/lib.sh" ]; then . "$HERE/lib.sh"; else
  SYSCONFDIR="${SYSCONFDIR:-/etc/syntriass}"
  LEN_ED25519_SEED=64; LEN_MLDSA65_SEED=64; LEN_PEER_ED25519=64; LEN_PEER_MLDSA65=3904
  log(){ printf '[syntriass] %s\n' "$*"; }; die(){ printf '[syntriass] FATAL: %s\n' "$*" >&2; exit 1; }
  toml_get(){ local f="$1" k="$2" r; [ -f "$f" ] || { echo ""; return 0; }; r="$(sed -n "s/^[[:space:]]*${k}[[:space:]]*=[[:space:]]*//p" "$f"|head -1)"; case "$r" in \"*) printf '%s' "${r#\"}"|sed 's/".*$//';; *) printf '%s' "$r"|sed 's/[[:space:]]*#.*$//;s/[[:space:]]*$//';; esac; }
  is_hex_len(){ [ "${#1}" -eq "$2" ] && printf '%s' "$1"|grep -qiE '^[0-9a-f]+$'; }
fi

rc=0
fail() { printf '[syntriass]  [FAIL] %s\n' "$*" >&2; rc=1; }
ok()   { printf '[syntriass]  [ OK ] %s\n' "$*"; }

POLICY="${SYSCONFDIR}/policy.toml"
IDENT="${SYSCONFDIR}/identity.toml"

log "validating configuration in ${SYSCONFDIR}"

# --- suite ---
suite="${SYNTRIASS_SUITE:-$(toml_get "$POLICY" suite)}"
case "$suite" in
  nist768|nist1024|0x01|0x02|768|1024) ok "suite = ${suite}";;
  "") fail "no suite set (policy.toml 'suite' or SYNTRIASS_SUITE)";;
  *)  fail "unknown suite '${suite}' (want nist768|nist1024)";;
esac

# --- identity: env overrides file (same precedence as the daemon) ---
get_id() { # <env-name> <toml-key>
  local v="${!1:-}"
  [ -n "$v" ] && { printf '%s' "$v"; return; }
  toml_get "$IDENT" "$2"
}
ed_seed="$(get_id SYNTRIASS_ED25519_SEED_HEX ed25519_seed)"
ml_seed="$(get_id SYNTRIASS_MLDSA65_SEED_HEX mldsa65_seed)"
peer_ed="$(get_id SYNTRIASS_PEER_ED25519_PUB_HEX peer_ed25519_public)"
peer_ml="$(get_id SYNTRIASS_PEER_MLDSA65_PUB_HEX peer_mldsa65_public)"

check() { # <name> <value> <len>
  if [ -z "$2" ]; then fail "$1 is empty (provision it; see DEPLOYMENT_GUIDE.md)"
  elif is_hex_len "$2" "$3"; then ok "$1 present (${3} hex chars)"
  else fail "$1 wrong size/format (want ${3} hex chars, got ${#2})"; fi
}
check "ed25519_seed"        "$ed_seed" "$LEN_ED25519_SEED"
check "mldsa65_seed"        "$ml_seed" "$LEN_MLDSA65_SEED"
check "peer_ed25519_public" "$peer_ed" "$LEN_PEER_ED25519"
check "peer_mldsa65_public" "$peer_ml" "$LEN_PEER_MLDSA65"

# reject the all-zero placeholder seed (weak/uninitialised identity)
case "$ed_seed$ml_seed" in *[!0]*) :;; "") :;; *) fail "identity seeds are all zero (placeholder) — provision a real identity";; esac

# --- secret hygiene ---
if [ -f "$IDENT" ]; then
  mode="$(stat -c '%a' "$IDENT" 2>/dev/null || echo '?')"
  case "$mode" in 600|400|640|440) ok "identity.toml mode ${mode}";;
    *) printf '[syntriass]  [WARN] identity.toml mode %s (recommend 600)\n' "$mode" >&2;; esac
fi

[ "$rc" -eq 0 ] && log "configuration VALID" || log "configuration INVALID"
exit "$rc"
