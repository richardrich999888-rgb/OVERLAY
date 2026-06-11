#!/usr/bin/env bash
#
# Universal-interception coverage validation for the Syntriass eBPF data plane.
#
# Proves, by MEASUREMENT, that a single `cgroup/connect4` eBPF program observes
# (and can enforce on) every outbound connect() regardless of how the calling
# process was built — glibc, static glibc, musl, Go, Rust, or a raw syscall that
# bypasses libc entirely (the case LD_PRELOAD cannot see).
#
# Requires (host, not the main CI sandbox): root or CAP_BPF+CAP_SYS_ADMIN, a
# kernel with cgroup v2 + BPF_PROG_TYPE_CGROUP_SOCK_ADDR (>=4.17; this was run on
# 6.18), clang, libbpf-dev, and the per-runtime toolchains (gcc, go, rustc +
# x86_64-unknown-linux-musl, python3). Toolchains that are absent are skipped and
# reported as SKIP — never as covered.
#
# Output: a coverage table + an enforcement check. Exit non-zero if any AVAILABLE
# runtime's connect was NOT observed, or if enforcement did not deny.
set -uo pipefail

HERE="$(cd "$(dirname "$0")/.." && pwd)"
CDIR="$HERE/ebpf/c"
MX="$CDIR/testmatrix"
WORK="$(mktemp -d)"
CG2="$WORK/cg2"
trap 'set +e; [ -n "${LOADER_PID:-}" ] && kill "$LOADER_PID" 2>/dev/null;
      [ -n "${SRV_PID:-}" ] && kill "$SRV_PID" 2>/dev/null;
      umount "$CG2" 2>/dev/null; rm -rf "$WORK"' EXIT

fail() { echo "FATAL: $*" >&2; exit 2; }

# ---- 1. build the BPF program + loader --------------------------------------
"$CDIR/build.sh" >/dev/null || fail "eBPF build failed (need clang + libbpf-dev)"
cp "$CDIR/connect4.bpf.o" "$WORK/" ; cp "$CDIR/loader" "$WORK/"

# ---- 2. build whatever runtimes are available -------------------------------
declare -A BIN PORT RUNNER
add() { BIN[$1]="$2"; PORT[$1]="$3"; RUNNER[$1]="$4"; }

# glibc dynamic + static glibc
if command -v gcc >/dev/null; then
  gcc -O2 "$MX/mx_c.c" -o "$WORK/mx_glibc" 2>/dev/null      && add glibc        "$WORK/mx_glibc"  51001 "$WORK/mx_glibc"
  gcc -O2 -static "$MX/mx_c.c" -o "$WORK/mx_static" 2>/dev/null && add static-glibc "$WORK/mx_static" 51002 "$WORK/mx_static"
  gcc -O2 "$MX/mx_direct.c" -o "$WORK/mx_direct" 2>/dev/null && add direct-syscall "$WORK/mx_direct" 51006 "$WORK/mx_direct"
fi
# Go (no libc; raw syscalls)
if command -v go >/dev/null; then
  ( cd "$WORK" && GOFLAGS=-mod=mod CGO_ENABLED=0 go build -o mx_go "$MX/mx_go.go" ) 2>/dev/null \
    && add go "$WORK/mx_go" 51003 "$WORK/mx_go"
fi
# Rust glibc + Rust musl-static
if command -v rustc >/dev/null; then
  rustc -O "$MX/mx_rust.rs" -o "$WORK/mx_rust" 2>/dev/null && add rust "$WORK/mx_rust" 51004 "$WORK/mx_rust"
  if rustc --print target-list 2>/dev/null | grep -q x86_64-unknown-linux-musl \
     && rustc -O --target x86_64-unknown-linux-musl "$MX/mx_rust.rs" -o "$WORK/mx_rustmusl" 2>/dev/null; then
    add rust-musl "$WORK/mx_rustmusl" 51005 "$WORK/mx_rustmusl"
  fi
fi
# Python (glibc via interpreter)
if command -v python3 >/dev/null; then
  cat > "$WORK/mx_py.py" <<'PY'
import socket,sys
s=socket.socket(); s.settimeout(0.3)
try:
    s.connect(("127.0.0.1", int(sys.argv[1]))); print("MX rc=0 errno=0(ok)")
except OSError as e:
    print(f"MX rc=-1 errno={e.errno}({e.strerror})"); sys.exit(e.errno or 1)
PY
  add python "python3 $WORK/mx_py.py" 51007 "python3 $WORK/mx_py.py"
fi

[ "${#BIN[@]}" -gt 0 ] || fail "no runtimes available to test"

# ---- 3. mount a private cgroup v2 + a probe sub-cgroup -----------------------
mkdir -p "$CG2"
mount -t cgroup2 nodev "$CG2" 2>/dev/null || fail "cannot mount cgroup2 (need CAP_SYS_ADMIN)"
mkdir -p "$CG2/probe"

# ---- 4. start the observer (observe-only) -----------------------------------
( cd "$WORK" && ./loader "$CG2/probe" 6000 0 ) >"$WORK/events.log" 2>"$WORK/loader.err" &
LOADER_PID=$!
for _ in $(seq 1 60); do grep -q READY "$WORK/loader.err" && break; sleep 0.1; done
grep -q READY "$WORK/loader.err" || { cat "$WORK/loader.err" >&2; fail "loader did not attach"; }

# ---- 5. run every runtime INSIDE the cgroup ---------------------------------
# Move this shell into the probe cgroup so all children inherit it.
echo $$ > "$CG2/probe/cgroup.procs" || fail "cannot join cgroup"
ORDER=(glibc static-glibc musl rust-musl go rust direct-syscall python)
for name in glibc static-glibc go rust rust-musl direct-syscall python; do
  [ -n "${BIN[$name]:-}" ] || continue
  ${RUNNER[$name]} "${PORT[$name]}" >/dev/null 2>&1 || true
done
sleep 0.5
# Move back out before teardown.
echo $$ > "$CG2/cgroup.procs" 2>/dev/null || true
wait "$LOADER_PID"; LOADER_PID=""

# ---- 6. coverage table ------------------------------------------------------
echo
echo "================ UNIVERSAL INTERCEPTION COVERAGE (measured) ================"
printf "%-16s %-7s %-9s %s\n" "runtime" "port" "observed" "evidence (comm/dst from eBPF)"
rc=0
for name in glibc static-glibc go rust rust-musl direct-syscall python; do
  if [ -z "${BIN[$name]:-}" ]; then
    printf "%-16s %-7s %-9s %s\n" "$name" "-" "SKIP" "(toolchain not present on this host)"
    continue
  fi
  p="${PORT[$name]}"
  line="$(grep ":$p " "$WORK/events.log" | head -1 || true)"
  if [ -n "$line" ]; then
    printf "%-16s %-7s %-9s %s\n" "$name" "$p" "YES" "$(echo "$line" | sed 's/^EVT //')"
  else
    printf "%-16s %-7s %-9s %s\n" "$name" "$p" "NO" "!! connect not observed by eBPF !!"
    rc=1
  fi
done
echo "total events captured: $(grep -c '^EVT ' "$WORK/events.log")"

# ---- 7. enforcement check (fail-closed deny) --------------------------------
echo
echo "================ ENFORCEMENT (fail-closed deny) ================"
# A real listener on the blocked port: a normal connect would SUCCEED; under the
# eBPF deny it must fail with EPERM (1).
BLOCK=51999
python3 - "$BLOCK" <<'PY' &
import socket,sys,time
srv=socket.socket(); srv.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
srv.bind(("127.0.0.1",int(sys.argv[1]))); srv.listen(8)
time.sleep(8)
PY
SRV_PID=$!
sleep 0.4
( cd "$WORK" && ./loader "$CG2/probe" 3000 "$BLOCK" ) >"$WORK/enf.log" 2>"$WORK/enf.err" &
LOADER_PID=$!
for _ in $(seq 1 60); do grep -q READY "$WORK/enf.err" && break; sleep 0.1; done
echo $$ > "$CG2/probe/cgroup.procs" || true
# Baseline: a port that is NOT blocked but has a listener would connect; we test
# the blocked port directly.
ENF_OUT="$("$WORK/mx_glibc" "$BLOCK" 2>&1 || true)"
echo $$ > "$CG2/cgroup.procs" 2>/dev/null || true
wait "$LOADER_PID"; LOADER_PID=""
kill "$SRV_PID" 2>/dev/null; SRV_PID=""

echo "blocked port $BLOCK had a LIVE listener; connect result under eBPF deny:"
echo "  $ENF_OUT"
if echo "$ENF_OUT" | grep -q "errno=1("; then
  echo "  -> EPERM: connection DENIED by eBPF despite a live server (fail-closed OK)"
  echo "  -> eBPF event: $(grep ":$BLOCK " "$WORK/enf.log" | head -1 | sed 's/^EVT //')"
else
  echo "  -> ENFORCEMENT FAILED (expected EPERM/errno=1)"; rc=1
fi

echo
[ "$rc" -eq 0 ] && echo "RESULT: PASS — every available runtime intercepted; enforcement denied." \
               || echo "RESULT: FAIL — see rows above."
exit "$rc"
