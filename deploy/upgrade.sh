#!/usr/bin/env bash
# Upgrade an installed SYNTRIASS Overlay: back up the current binaries, install
# the new ones, re-validate the (unchanged) config, and restart the service.
# Config and identity are never touched. Fail-closed: if validation fails, the
# upgrade aborts and the previous binaries are restored.
#
#   upgrade.sh --from <dir-with-new-binaries>
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/lib.sh"

FROM=""
[ "${1:-}" = "--from" ] && { FROM="$2"; shift 2; }
[ -n "$FROM" ] || die "usage: upgrade.sh --from <dir-with-new-binaries>"
[ "$(id -u)" -eq 0 ] || die "upgrade must run as root"
for b in daemon syntriass-identity webhook; do [ -f "$FROM/$b" ] || die "missing $FROM/$b"; done

TS="$(date -u +%Y%m%dT%H%M%SZ)"
BK="$BACKUPDIR/$TS"
install -d -m 0750 "$BK"

log "backing up current binaries to $BK"
for ib in "$BIN_DAEMON" "$BIN_IDENTITY" "$BIN_WEBHOOK" "$VALIDATE_BIN"; do
  [ -f "$PREFIX/bin/$ib" ] && cp -a "$PREFIX/bin/$ib" "$BK/$ib"
done
echo "$FROM" > "$BK/.source"

log "installing new binaries"
install -m 0755 "$FROM/daemon"            "$PREFIX/bin/$BIN_DAEMON"
install -m 0755 "$FROM/syntriass-identity" "$PREFIX/bin/$BIN_IDENTITY"
install -m 0755 "$FROM/webhook"           "$PREFIX/bin/$BIN_WEBHOOK"
install -m 0755 "$HERE/validate-config.sh" "$PREFIX/bin/$VALIDATE_BIN"

log "validating config against the new binaries"
if ! "$PREFIX/bin/$VALIDATE_BIN"; then
  warn "validation FAILED — rolling back this upgrade"
  for ib in "$BIN_DAEMON" "$BIN_IDENTITY" "$BIN_WEBHOOK" "$VALIDATE_BIN"; do
    [ -f "$BK/$ib" ] && cp -a "$BK/$ib" "$PREFIX/bin/$ib"
  done
  die "upgrade aborted; previous binaries restored from $BK"
fi

ln -sfn "$TS" "$BACKUPDIR/latest"
if have_systemd && systemctl is-enabled "$SERVICE" >/dev/null 2>&1; then
  log "restarting $SERVICE"
  systemctl restart "$SERVICE" && log "restarted" || warn "restart failed — check: journalctl -u $SERVICE"
else
  log "service not managed by systemd here; restart the daemon manually"
fi
log "upgrade complete (backup: $BK). Roll back with: rollback.sh"
