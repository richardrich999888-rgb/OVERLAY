#!/usr/bin/env bash
set -euo pipefail

source "$(dirname "$0")/common.sh"
COUNT="${SYNTRIASS_PERF_COUNT:-25}"
OUT="$ARTIFACT_DIR/performance.jsonl"
mkdir -p "$ARTIFACT_DIR"

measure() {
  local workload="$1"
  local cmd="$2"
  local start end rc
  start="$(python3 -c 'import time; print(time.perf_counter_ns())')"
  set +e
  /usr/bin/time -p bash -c "$cmd" >"$ARTIFACT_DIR/logs/perf-$workload.stdout" 2>"$ARTIFACT_DIR/logs/perf-$workload.time"
  rc=$?
  set -e
  end="$(python3 -c 'import time; print(time.perf_counter_ns())')"
  python3 - "$OUT" "$workload" "$rc" "$start" "$end" "$ARTIFACT_DIR/logs/perf-$workload.time" <<'PY'
import json, sys
out, workload, rc, start, end, time_file = sys.argv[1:]
metrics = {}
for line in open(time_file, errors="ignore"):
    parts = line.split()
    if len(parts) == 2:
        metrics[parts[0]] = float(parts[1])
metrics.update({
    "workload": workload,
    "exit_code": int(rc),
    "wall_ns": int(end) - int(start),
})
with open(out, "a") as f:
    f.write(json.dumps(metrics, sort_keys=True) + "\n")
PY
}

for workload in python syscall; do
  case "$workload" in
    python) cmd="for i in \$(seq 1 $COUNT); do python3 '$ROOT/validation/workloads/python_client/client.py' '$SERVER_HOST' '$SERVER_PORT' '$PLAINTEXT_MARKER' >/dev/null || true; done" ;;
    syscall) cmd="for i in \$(seq 1 $COUNT); do '$ROOT/validation/bin/direct_syscall_client' '$SERVER_HOST' '$SERVER_PORT' '$PLAINTEXT_MARKER' >/dev/null || true; done" ;;
  esac
  measure "$workload" "echo \\\$\\\$ > '$CGROUP_PATH/cgroup.procs'; $cmd"
done
