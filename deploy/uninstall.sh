#!/usr/bin/env bash
# Remove SYNTRIASS Overlay. Stops + disables the service and removes binaries and
# the unit. By default KEEPS /etc/syntriass (identity/config) and state; pass
# --purge to remove them too.
#
#   uninstall.sh [--purge]
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/lib.sh"

PURGE=0
[ "${1:-}" = "--purge" ] && PURGE=1
[ "$(id -u)" -eq 0 ] || die "uninstall must run as root"

if have_systemd; then
  systemctl disable --now "$SERVICE" 2>/dev/null || true
  systemctl daemon-reload 2>/dev/null || true
fi
rm -f "$UNITDIR/$SERVICE"
for ib in "$BIN_DAEMON" "$BIN_IDENTITY" "$BIN_WEBHOOK" "$VALIDATE_BIN" syntriass-overlay-lib.sh; do
  rm -f "$PREFIX/bin/$ib"
done
log "removed binaries + unit"

if [ "$PURGE" -eq 1 ]; then
  rm -rf "$SYSCONFDIR" "$STATEDIR"
  log "purged $SYSCONFDIR and $STATEDIR"
  id "$SVC_USER" >/dev/null 2>&1 && userdel "$SVC_USER" 2>/dev/null || true
else
  log "kept $SYSCONFDIR (config/identity) and $STATEDIR — pass --purge to remove"
fi
log "uninstall complete"
