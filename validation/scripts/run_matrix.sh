#!/usr/bin/env bash
set -euo pipefail

source "$(dirname "$0")/common.sh"
need_root

cd "$ROOT"
rm -rf "$ARTIFACT_DIR"
mkdir -p "$ARTIFACT_DIR"/{audit,pcap,logs,report,run}
ln -sfn "$ARTIFACT_DIR" "$ARTIFACT_ROOT/latest"

mkdir -p "$CGROUP_PATH" "$PIN_PATH"
CGROUP_ID="$(cgroup_id)"
MATRIX="$ARTIFACT_DIR/matrix.jsonl"
DAEMON_LOG="$ARTIFACT_DIR/audit/syntriass-daemon.jsonl"
SERVER_LOG="$ARTIFACT_DIR/logs/server.log"

log "cgroup=$CGROUP_PATH cgroup_id=$CGROUP_ID"

python3 validation/workloads/tcp_server.py "$SERVER_HOST" "$SERVER_PORT" "$PLAINTEXT_MARKER" >"$SERVER_LOG" 2>&1 &
SERVER_PID=$!
trap 'kill "$SERVER_PID" >/dev/null 2>&1 || true; [[ -n "${DAEMON_PID:-}" ]] && kill "$DAEMON_PID" >/dev/null 2>&1 || true; [[ -n "${TCPDUMP_PID:-}" ]] && kill "$TCPDUMP_PID" >/dev/null 2>&1 || true' EXIT
sleep 1

log "baseline plaintext capture before SYNTRIASS"
BASELINE_PCAP="$ARTIFACT_DIR/pcap/baseline_plaintext_before_syntriass.pcap"
tcpdump -i "$IFACE" -w "$BASELINE_PCAP" "tcp and host $SERVER_HOST and port $SERVER_PORT" >/dev/null 2>&1 &
TCPDUMP_PID=$!
sleep 1
python3 validation/workloads/python_client/client.py "$SERVER_HOST" "$SERVER_PORT" "$PLAINTEXT_MARKER" >"$ARTIFACT_DIR/logs/baseline.stdout" 2>"$ARTIFACT_DIR/logs/baseline.stderr" || true
sleep 1
kill "$TCPDUMP_PID" >/dev/null 2>&1 || true
wait "$TCPDUMP_PID" 2>/dev/null || true
TCPDUMP_PID=""

SYNTRIASS_EBPF_OBJECT="$ROOT/ebpf/target/bpfel-unknown-none/release/syntriass-ebpf" \
SYNTRIASS_CGROUP_PATH="$CGROUP_PATH" \
SYNTRIASS_MAP_PIN_PATH="$PIN_PATH" \
"$ROOT/target/release/daemon" >"$DAEMON_LOG" 2>&1 &
DAEMON_PID=$!
sleep 2

pcap_start() {
  local name="$1"
  local pcap="$ARTIFACT_DIR/pcap/$name.pcap"
  tcpdump -i "$IFACE" -w "$pcap" "tcp and host $SERVER_HOST and port $SERVER_PORT" >/dev/null 2>&1 &
  TCPDUMP_PID=$!
  sleep 1
}

pcap_stop() {
  sleep 1
  kill "$TCPDUMP_PID" >/dev/null 2>&1 || true
  wait "$TCPDUMP_PID" 2>/dev/null || true
  TCPDUMP_PID=""
}

clear_policy_session() {
  "$ROOT/target/release/syntriassctl" policy remove --cgroup-id "$CGROUP_ID" --ip "$SERVER_HOST" --port "$SERVER_PORT" >/dev/null 2>&1 || true
}

add_allow_policy() {
  "$ROOT/target/release/syntriassctl" policy add --cgroup-id "$CGROUP_ID" --ip "$SERVER_HOST" --port "$SERVER_PORT" --allow >/dev/null
}

establish_session() {
  local cookie="$1"
  "$ROOT/target/release/syntriassctl" session establish --socket-cookie "$cookie" --ttl-secs 60 >/dev/null
}

expire_session() {
  local cookie="$1"
  "$ROOT/target/release/syntriassctl" session establish --socket-cookie "$cookie" --ttl-secs 0 >/dev/null
}

latest_cookie() {
  python3 - "$DAEMON_LOG" <<'PY'
import json, sys
cookie = 0
for line in open(sys.argv[1], errors="ignore"):
    try:
        obj = json.loads(line)
    except Exception:
        continue
    if obj.get("socket_cookie"):
        cookie = obj["socket_cookie"]
print(cookie)
PY
}

client_cmd() {
  case "$1" in
    go) echo "$ROOT/validation/bin/static_go_client $SERVER_HOST:$SERVER_PORT $PLAINTEXT_MARKER" ;;
    rust) echo "$ROOT/validation/bin/static_rust_client $SERVER_HOST:$SERVER_PORT $PLAINTEXT_MARKER" ;;
    python) echo "python3 $ROOT/validation/workloads/python_client/client.py $SERVER_HOST $SERVER_PORT $PLAINTEXT_MARKER" ;;
    syscall) echo "$ROOT/validation/bin/direct_syscall_client $SERVER_HOST $SERVER_PORT $PLAINTEXT_MARKER" ;;
    container) echo "docker run --rm --network host --cgroup-parent=/syntriass-validation syntriass-validation-client $SERVER_HOST $SERVER_PORT $PLAINTEXT_MARKER" ;;
    *) echo "unknown workload $1" >&2; exit 2 ;;
  esac
}

run_attempt() {
  local scenario="$1"
  local workload="$2"
  local expected="$3"
  local pcap_name="$scenario-$workload"
  local stdout="$ARTIFACT_DIR/logs/$pcap_name.stdout"
  local stderr="$ARTIFACT_DIR/logs/$pcap_name.stderr"
  local before after exit_code audit_count plaintext
  before="$(wc -l <"$DAEMON_LOG" | tr -d ' ')"
  pcap_start "$pcap_name"
  set +e
  in_validation_cgroup "$(client_cmd "$workload")" >"$stdout" 2>"$stderr"
  exit_code=$?
  set -e
  pcap_stop
  after="$(wc -l <"$DAEMON_LOG" | tr -d ' ')"
  audit_count=$((after - before))
  if tcpdump -A -r "$ARTIFACT_DIR/pcap/$pcap_name.pcap" 2>/dev/null | grep -q "$PLAINTEXT_MARKER"; then
    plaintext=true
  else
    plaintext=false
  fi
  python3 validation/scripts/record_result.py "$MATRIX" "$scenario" "$workload" "$expected" "$exit_code" "$audit_count" "$plaintext" "$ARTIFACT_DIR/pcap/$pcap_name.pcap" "$stdout" "$stderr"
}

run_scenario() {
  local scenario="$1"
  local policy="$2"
  local session="$3"
  local expected="$4"
  local workload="$5"

  clear_policy_session
  if [[ "$policy" == "allow" ]]; then
    add_allow_policy
  fi

  if [[ "$session" == "present" || "$session" == "expired" ]]; then
    run_attempt "$scenario-prime" "$workload" "blocked"
    COOKIE="$(latest_cookie)"
    if [[ "$COOKIE" == "0" ]]; then
      log "scenario=$scenario workload=$workload no socket_cookie available"
    elif [[ "$session" == "present" ]]; then
      establish_session "$COOKIE"
    else
      expire_session "$COOKIE"
    fi
  fi

  run_attempt "$scenario" "$workload" "$expected"
}

WORKLOADS=(go rust python syscall)
if command -v docker >/dev/null 2>&1 && docker image inspect syntriass-validation-client >/dev/null 2>&1; then
  WORKLOADS+=(container)
fi

for workload in "${WORKLOADS[@]}"; do
  run_scenario "A_policy_allow_session_established" allow present success "$workload"
  run_scenario "B_policy_allow_session_missing" allow missing blocked "$workload"
  run_scenario "C_policy_missing_session_present" missing present blocked "$workload"
  run_scenario "D_policy_missing_session_missing" missing missing blocked "$workload"
  run_scenario "E_session_expired" allow expired blocked "$workload"
done

validation/scripts/run_adversarial.sh || true
validation/scripts/run_performance.sh || true

log "daemon crash scenario"
kill "$DAEMON_PID" >/dev/null 2>&1 || true
wait "$DAEMON_PID" 2>/dev/null || true
DAEMON_PID=""
run_scenario "F_daemon_crash" allow missing blocked python

python3 validation/scripts/generate_report.py "$ARTIFACT_DIR"
log "validation artifacts: $ARTIFACT_DIR"
