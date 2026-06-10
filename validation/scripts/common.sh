#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
VALIDATION="$ROOT/validation"
ARTIFACT_ROOT="$VALIDATION/artifacts"
ARTIFACT_DIR="${ARTIFACT_DIR:-$ARTIFACT_ROOT/latest}"
CGROUP_PATH="${SYNTRIASS_VALIDATION_CGROUP:-/sys/fs/cgroup/syntriass-validation}"
PIN_PATH="${SYNTRIASS_MAP_PIN_PATH:-/sys/fs/bpf/syntriass}"
SERVER_HOST="${SYNTRIASS_SERVER_HOST:-127.0.0.1}"
SERVER_PORT="${SYNTRIASS_SERVER_PORT:-19090}"
IFACE="${SYNTRIASS_CAPTURE_IFACE:-lo}"
PLAINTEXT_MARKER="${SYNTRIASS_PLAINTEXT_MARKER:-SYNTRIASS_PLAINTEXT_MARKER}"

mkdir -p "$ARTIFACT_DIR"/{audit,pcap,logs,report,run}

log() {
  printf '[syntriass-validation] %s\n' "$*" >&2
}

need_root() {
  if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    echo "this script must run as root" >&2
    exit 1
  fi
}

cgroup_id() {
  stat -Lc '%i' "$CGROUP_PATH"
}

in_validation_cgroup() {
  local cmd="$1"
  bash -c "echo \\\$\\\$ > '$CGROUP_PATH/cgroup.procs'; exec $cmd"
}

json_escape() {
  python3 -c 'import json,sys; print(json.dumps(sys.stdin.read())[1:-1])'
}
