#!/usr/bin/env bash
set -euo pipefail

source "$(dirname "$0")/common.sh"
need_root

ADV="$ARTIFACT_DIR/adversarial.jsonl"
mkdir -p "$ARTIFACT_DIR"

record() {
  local name="$1"
  local exit_code="$2"
  local expected="$3"
  python3 - "$ADV" "$name" "$exit_code" "$expected" <<'PY'
import json, sys
path, name, exit_code, expected = sys.argv[1:]
observed = "success" if int(exit_code) == 0 else "blocked"
with open(path, "a") as f:
    f.write(json.dumps({
        "test": name,
        "expected": expected,
        "observed": observed,
        "pass": observed == expected,
    }, sort_keys=True) + "\n")
PY
}

set +e
LD_PRELOAD= in_validation_cgroup "python3 '$ROOT/validation/workloads/python_client/client.py' '$SERVER_HOST' '$SERVER_PORT' '$PLAINTEXT_MARKER'"
record "ld_preload_disabled" "$?" "blocked"

in_validation_cgroup "$ROOT/validation/bin/direct_syscall_client '$SERVER_HOST' '$SERVER_PORT' '$PLAINTEXT_MARKER'"
record "direct_syscall_connect" "$?" "blocked"

bash -c "echo \\\$\\\$ > '$CGROUP_PATH/cgroup.procs'; exec python3 '$ROOT/validation/workloads/python_client/client.py' '$SERVER_HOST' '$SERVER_PORT' '$PLAINTEXT_MARKER'"
record "fork_exec_after_cgroup_assignment" "$?" "blocked"

if command -v unshare >/dev/null 2>&1; then
  unshare -n bash -c "echo \\\$\\\$ > '$CGROUP_PATH/cgroup.procs'; exec python3 '$ROOT/validation/workloads/python_client/client.py' '$SERVER_HOST' '$SERVER_PORT' '$PLAINTEXT_MARKER'"
  record "namespace_transition" "$?" "blocked"
fi

echo $$ > "$CGROUP_PATH/cgroup.procs"
python3 "$ROOT/validation/workloads/python_client/client.py" "$SERVER_HOST" "$SERVER_PORT" "$PLAINTEXT_MARKER"
record "cgroup_reassignment" "$?" "blocked"
set -e
