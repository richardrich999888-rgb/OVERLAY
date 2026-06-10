#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 5 ]]; then
  echo "usage: $0 IFACE CGROUP_ID DEST_IP DEST_PORT SOCKET_COOKIE" >&2
  exit 2
fi

IFACE="$1"
CGROUP_ID="$2"
DEST_IP="$3"
DEST_PORT="$4"
SOCKET_COOKIE="$5"
PCAP="${PCAP:-/tmp/syntriass-phase3.pcap}"
PIN="${SYNTRIASS_MAP_PIN_PATH:-/sys/fs/bpf/syntriass}"

echo "[1/5] remove stale policy/session"
cargo run --bin syntriassctl -- policy remove \
  --cgroup-id "$CGROUP_ID" --ip "$DEST_IP" --port "$DEST_PORT" >/dev/null 2>&1 || true
cargo run --bin syntriassctl -- session remove \
  --socket-cookie "$SOCKET_COOKIE" >/dev/null 2>&1 || true

echo "[2/5] start packet capture: $PCAP"
tcpdump -i "$IFACE" -w "$PCAP" "tcp and host $DEST_IP and port $DEST_PORT" &
TCPDUMP_PID=$!
trap 'kill "$TCPDUMP_PID" >/dev/null 2>&1 || true' EXIT
sleep 1

echo "[3/5] install allow policy only; connect must still fail until SESSION_MAP is established"
cargo run --bin syntriassctl -- policy add \
  --cgroup-id "$CGROUP_ID" --ip "$DEST_IP" --port "$DEST_PORT" --allow

echo "[4/5] establish authenticated PQC session binding"
SYNTRIASS_MAP_PIN_PATH="$PIN" cargo run --bin syntriassctl -- session establish \
  --socket-cookie "$SOCKET_COOKIE" --ttl-secs 60

echo "[5/5] validate captured payloads contain no obvious plaintext marker"
sleep 2
kill "$TCPDUMP_PID" >/dev/null 2>&1 || true
trap - EXIT

if tcpdump -A -r "$PCAP" 2>/dev/null | grep -q "SYNTRIASS_PLAINTEXT_MARKER"; then
  echo "FAIL: plaintext marker observed in $PCAP" >&2
  exit 1
fi

echo "PASS: no SYNTRIASS_PLAINTEXT_MARKER observed in $PCAP"
