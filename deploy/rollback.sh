#!/usr/bin/env bash
# Roll back to the binaries saved by the most recent upgrade (or a named backup).
# Config/identity are untouched. Validates after restoring; restarts the service.
#
#   rollback.sh [<backup-timestamp>]   (default: the 'latest' upgrade backup)
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/lib.sh"

[ "$(id -u)" -eq 0 ] || die "rollback must run as root"
TS="${1:-}"
if [ -z "$TS" ]; then
  [ -e "$BACKUPDIR/latest" ] || die "no 'latest' backup; pass a timestamp (ls $BACKUPDIR)"
  TS="$(readlink "$BACKUPDIR/latest")"
fi
BK="$BACKUPDIR/$TS"
[ -d "$BK" ] || die "no backup at $BK"

log "restoring binaries from $BK"
restored=0
for ib in "$BIN_DAEMON" "$BIN_IDENTITY" "$BIN_WEBHOOK" "$VALIDATE_BIN"; do
  if [ -f "$BK/$ib" ]; then cp -a "$BK/$ib" "$PREFIX/bin/$ib"; restored=$((restored+1)); fi
done
[ "$restored" -gt 0 ] || die "backup $BK held no binaries"
log "restored $restored binaries"

if "$PREFIX/bin/$VALIDATE_BIN"; then log "config valid after rollback"; else warn "config invalid after rollback — check identity"; fi

if have_systemd && systemctl is-enabled "$SERVICE" >/dev/null 2>&1; then
  systemctl restart "$SERVICE" && log "restarted $SERVICE" || warn "restart failed — journalctl -u $SERVICE"
else
  log "restart the daemon manually"
fi
log "rollback to $TS complete"
