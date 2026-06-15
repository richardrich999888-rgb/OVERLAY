#!/usr/bin/env bash
# Air-gapped operations for SYNTRIASS Overlay — NO network is ever contacted.
# Provision identities, exchange public keys, and distribute policy across an
# air gap using removable media (sneakernet). Every transferred artifact carries
# a SHA-256 self-checksum that is verified on import.
#
# Subcommands:
#   export-identity <out-file>          write THIS node's PUBLIC identity (safe to carry)
#   import-peer     <peer-file>         set peer_* in identity.toml from a peer's export
#   make-policy-bundle <suite> <out>    build an offline, checksummed policy bundle
#   apply-policy-bundle <bundle-file>   verify + install a policy bundle (offline)
#   show-fingerprint                    print THIS node's identity fingerprint
HERE="$(cd "$(dirname "$0")" && pwd)"
if [ -f "$HERE/lib.sh" ]; then . "$HERE/lib.sh"; else
  PREFIX="${PREFIX:-/usr/local}"; SYSCONFDIR="${SYSCONFDIR:-/etc/syntriass}"
  BIN_IDENTITY="syntriass-identity"
  log(){ printf '[syntriass] %s\n' "$*"; }; die(){ printf '[syntriass] FATAL: %s\n' "$*" >&2; exit 1; }
  toml_get(){ local f="$1" k="$2" r; [ -f "$f" ]||{ echo ""; return 0; }; r="$(sed -n "s/^[[:space:]]*${k}[[:space:]]*=[[:space:]]*//p" "$f"|head -1)"; case "$r" in \"*) printf '%s' "${r#\"}"|sed 's/".*$//';; *) printf '%s' "$r"|sed 's/[[:space:]]*#.*$//;s/[[:space:]]*$//';; esac; }
fi

IDENT="${SYSCONFDIR}/identity.toml"
ID_BIN="${PREFIX}/bin/${BIN_IDENTITY}"
[ -x "$ID_BIN" ] || ID_BIN="$(command -v syntriass-identity || true)"

# Derive THIS node's public keys from its configured seeds (offline, local only).
own_pubs() {
  local eds mls
  eds="$(toml_get "$IDENT" ed25519_seed)"; mls="$(toml_get "$IDENT" mldsa65_seed)"
  [ -n "$eds" ] && [ -n "$mls" ] || die "no local seeds in $IDENT (provision first: install.sh --provision-self)"
  [ -x "$ID_BIN" ] || die "syntriass-identity not found"
  "$ID_BIN" "$eds" "$mls"
}

fingerprint() { # sha256 of ed||ml public, first 16 hex
  printf '%s%s' "$1" "$2" | sha256sum | cut -c1-16
}

cmd="${1:-}"; shift || true
case "$cmd" in
  show-fingerprint)
    p="$(own_pubs)"; ed="$(printf '%s\n' "$p"|sed -n 's/^ed25519_public=//p')"; ml="$(printf '%s\n' "$p"|sed -n 's/^mldsa65_public=//p')"
    log "this node fingerprint: $(fingerprint "$ed" "$ml")"
    ;;

  export-identity)
    out="${1:?usage: export-identity <out-file>}"
    p="$(own_pubs)"; ed="$(printf '%s\n' "$p"|sed -n 's/^ed25519_public=//p')"; ml="$(printf '%s\n' "$p"|sed -n 's/^mldsa65_public=//p')"
    fp="$(fingerprint "$ed" "$ml")"
    body="$(printf 'syntriass-identity-export v1\nlabel=%s\ned25519_public=%s\nmldsa65_public=%s\nfingerprint=%s' "$(hostname 2>/dev/null||echo node)" "$ed" "$ml" "$fp")"
    # checksum over the canonical body (one trailing newline), computed the same
    # way on import so the two agree byte-for-byte.
    sum="$(printf '%s\n' "$body" | sha256sum | cut -d' ' -f1)"
    { printf '%s\n' "$body"; printf 'sha256=%s\n' "$sum"; } > "$out"
    chmod 0644 "$out"
    log "exported PUBLIC identity to $out (fingerprint $fp). Carry it to the peer on removable media."
    ;;

  import-peer)
    pf="${1:?usage: import-peer <peer-file>}"
    [ -f "$pf" ] || die "no such file: $pf"
    grep -q '^syntriass-identity-export v1' "$pf" || die "$pf is not a v1 identity export"
    body="$(sed '/^sha256=/d' "$pf")"
    want="$(sed -n 's/^sha256=//p' "$pf" | tail -1)"
    got="$(printf '%s\n' "$body" | sha256sum | cut -d' ' -f1)"
    [ "$want" = "$got" ] || die "checksum mismatch on $pf (want $want got $got) — refusing import (fail closed)"
    ed="$(sed -n 's/^ed25519_public=//p' "$pf"|head -1)"; ml="$(sed -n 's/^mldsa65_public=//p' "$pf"|head -1)"
    [ "${#ed}" -eq 64 ] && [ "${#ml}" -eq 3904 ] || die "peer keys wrong size (ed=${#ed} ml=${#ml})"
    [ -f "$IDENT" ] || die "no $IDENT (install + provision-self first)"
    tmp="$(mktemp)"; awk -v ed="$ed" -v ml="$ml" '
      /^[[:space:]]*peer_ed25519_public[[:space:]]*=/ {print "peer_ed25519_public = \"" ed "\""; next}
      /^[[:space:]]*peer_mldsa65_public[[:space:]]*=/ {print "peer_mldsa65_public = \"" ml "\""; next}
      {print}
    ' "$IDENT" > "$tmp"
    grep -q '^peer_ed25519_public' "$tmp" || printf 'peer_ed25519_public = "%s"\n' "$ed" >> "$tmp"
    grep -q '^peer_mldsa65_public' "$tmp" || printf 'peer_mldsa65_public = "%s"\n' "$ml" >> "$tmp"
    cat "$tmp" > "$IDENT"; rm -f "$tmp"; chmod 0600 "$IDENT"
    log "imported peer (fingerprint $(fingerprint "$ed" "$ml")) into $IDENT. Now run: syntriass-overlay-validate-config"
    ;;

  make-policy-bundle)
    suite="${1:?usage: make-policy-bundle <suite> <out.tar.gz>}"; out="${2:?out path}"
    case "$suite" in nist768|nist1024) :;; *) die "suite must be nist768|nist1024";; esac
    stage="$(mktemp -d)"; trap 'rm -rf "$stage"' EXIT
    printf '# offline policy bundle\nsuite = "%s"\n' "$suite" > "$stage/policy.toml"
    ( cd "$stage" && sha256sum policy.toml > SHA256SUMS )
    tar czf "$out" -C "$stage" policy.toml SHA256SUMS
    log "policy bundle: $out (suite=$suite). Carry to target hosts; apply offline."
    ;;

  apply-policy-bundle)
    b="${1:?usage: apply-policy-bundle <bundle.tar.gz>}"
    [ -f "$b" ] || die "no such file: $b"
    stage="$(mktemp -d)"; trap 'rm -rf "$stage"' EXIT
    tar xzf "$b" -C "$stage"
    ( cd "$stage" && sha256sum -c SHA256SUMS >/dev/null 2>&1 ) || die "bundle checksum FAILED — refusing to apply (fail closed)"
    install -d -m 0750 "$SYSCONFDIR"
    install -m 0640 "$stage/policy.toml" "$SYSCONFDIR/policy.toml"
    log "applied policy bundle to $SYSCONFDIR/policy.toml (suite=$(toml_get "$SYSCONFDIR/policy.toml" suite))"
    ;;

  *) sed -n '2,16p' "$0"; exit 1;;
esac
