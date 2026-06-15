#!/usr/bin/env bash
# Build a self-contained, offline-installable SYNTRIASS Overlay package:
# a versioned tarball with the release binaries, the deploy scripts, the systemd
# unit, config templates, docs, a SHA256SUMS manifest, and a top-level install.sh.
# The resulting tarball can be copied to an air-gapped host and installed with no
# network and no source tree (Phase 5).
#
#   package.sh [--out <dir>]   (default ./dist)
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
. "$HERE/lib.sh"

OUT="$ROOT/dist"
[ "${1:-}" = "--out" ] && { OUT="$2"; shift 2; }

VERSION="$(sed -n 's/^version *= *"\(.*\)"/\1/p' "$ROOT/Cargo.toml" | head -1)"
ARCH="$(uname -m)"
NAME="syntriass-overlay-${VERSION}-${ARCH}"
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT

log "building release binaries"
( cd "$ROOT" && cargo build --release --locked >/dev/null ) || die "cargo build failed"

PKG="$STAGE/$NAME"
mkdir -p "$PKG/bin" "$PKG/deploy/systemd" "$PKG/deploy/config" "$PKG/docs"

# binaries (installed names)
install -m 0755 "$ROOT/target/release/daemon"            "$PKG/bin/$BIN_DAEMON"
install -m 0755 "$ROOT/target/release/syntriass-identity" "$PKG/bin/$BIN_IDENTITY"
install -m 0755 "$ROOT/target/release/webhook"           "$PKG/bin/$BIN_WEBHOOK"

# deploy assets
for s in install.sh validate-config.sh upgrade.sh rollback.sh uninstall.sh lib.sh; do
  install -m 0755 "$HERE/$s" "$PKG/deploy/$s"
done
install -m 0644 "$HERE/systemd/$SERVICE"            "$PKG/deploy/systemd/$SERVICE"
install -m 0644 "$HERE/config/policy.toml.template"  "$PKG/deploy/config/policy.toml.template"
install -m 0644 "$HERE/config/identity.toml.template" "$PKG/deploy/config/identity.toml.template"
for dgm in DEPLOYMENT_GUIDE.md AIR_GAPPED_OPERATIONS.md FLEET_MANAGEMENT.md; do
  [ -f "$ROOT/docs/$dgm" ] && install -m 0644 "$ROOT/docs/$dgm" "$PKG/docs/$dgm" || true
done

# top-level installer shim: binaries already built, install from ./bin
cat > "$PKG/install.sh" <<'SHIM'
#!/usr/bin/env bash
# Offline installer shim — installs the prebuilt binaries in ./bin.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
exec "$HERE/deploy/install.sh" --from "$HERE/bin" "$@"
SHIM
chmod 0755 "$PKG/install.sh"

echo "$VERSION" > "$PKG/VERSION"

# checksums over every file (for offline integrity verification)
( cd "$PKG" && find . -type f ! -name SHA256SUMS -print0 | sort -z \
    | xargs -0 sha256sum > SHA256SUMS )

mkdir -p "$OUT"
TARBALL="$OUT/${NAME}.tar.gz"
( cd "$STAGE" && tar czf "$TARBALL" "$NAME" )
( cd "$OUT" && sha256sum "$(basename "$TARBALL")" > "${NAME}.tar.gz.sha256" )

log "package: $TARBALL"
log "sha256 : $(cut -d' ' -f1 "$OUT/${NAME}.tar.gz.sha256")"
log "size   : $(du -h "$TARBALL" | cut -f1)"
