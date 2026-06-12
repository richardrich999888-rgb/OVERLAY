#!/usr/bin/env bash
#
# eBPF Policy Engine v2 — Phase 1 (Policy Object Model) validation.
#
# Proves, by MEASUREMENT, that egress is driven by a STRUCTURED policy object
# (`struct syntriass_policy`) held in a BPF hash map, distributed from userspace
# and enforced by the kernel cgroup/connect4 hook. Four object-model decision
# paths are each proven with a REAL connect through the live hook:
#
#   probe   + FullPqc  policy object        -> ALLOW  (reaches net: errno 111)
#   probe   + FailClosed policy object       -> DENY   (EPERM: errno 1)
#   expired + already-expired policy object  -> DENY   (REASON_EXPIRED, errno 1)
#   nopolicy (no policy object at all)        -> DENY   (map-miss fail-closed, errno 1)
#
# and reports the measured LOOKUP (kernel run-time accounting over a real connect
# burst), UPDATE (full-object push), and MEMORY (value size x capacity) costs.
#
# Requires (host, not the default sandbox): root/CAP_BPF+CAP_SYS_ADMIN, cgroup v2
# with CGROUP_SOCK_ADDR, clang, libbpf-dev, gcc.
set -uo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"
CDIR="$HERE/ebpf/c"
WORK="$(mktemp -d)"
CG2="$WORK/cg2"
declare -i RC=0
LOADER_PID=""
trap 'set +e; [ -n "$LOADER_PID" ] && kill "$LOADER_PID" 2>/dev/null; umount "$CG2" 2>/dev/null; rm -rf "$WORK"' EXIT
fail() { echo "FATAL: $*" >&2; exit 2; }

"$CDIR/build.sh" >/dev/null || fail "eBPF build failed (need clang + libbpf-dev)"
cp "$CDIR/policy_v2.bpf.o" "$CDIR/policy_v2_loader" "$WORK/"
gcc -O2 "$CDIR/testmatrix/mx_c.c" -o "$WORK/mx" 2>/dev/null || fail "need gcc for the connect probe"

# Burst probe: N connects to a refused port, to converge the kernel's per-program
# run-time accounting (real traffic through the hook).
cat > "$WORK/burst.c" <<'EOF'
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <stdlib.h>
int main(int argc, char** argv){
    int n = argc>1?atoi(argv[1]):10000;
    int port = argc>2?atoi(argv[2]):51900;
    struct sockaddr_in sa; memset(&sa,0,sizeof sa);
    sa.sin_family=AF_INET; sa.sin_port=htons(port);
    inet_pton(AF_INET,"127.0.0.1",&sa.sin_addr);
    for(int i=0;i<n;i++){ int fd=socket(AF_INET,SOCK_STREAM,0);
        if(fd<0) continue; connect(fd,(struct sockaddr*)&sa,sizeof sa); close(fd); }
    return 0;
}
EOF
gcc -O2 "$WORK/burst.c" -o "$WORK/burst" 2>/dev/null || fail "need gcc for the burst probe"

mkdir -p "$CG2"
mount -t cgroup2 nodev "$CG2" 2>/dev/null || fail "cannot mount cgroup2 (need CAP_SYS_ADMIN)"
mkdir -p "$CG2/probe" "$CG2/expired" "$CG2/nopolicy"

# Schedule: probe starts FullPqc (installed at load); rewrite its policy OBJECT to
# FailClosed (2) at t=2500 ms (a full structured-object rewrite, timed).
printf '2500 2\n' > "$WORK/schedule"

echo "============ eBPF POLICY ENGINE v2 — Phase 1 (measured) ============"

# ---- pass 0: isolated policy lookup + decision cost (lookup-only program) ----
( cd "$WORK" && ./policy_v2_loader bench "$CG2" "$CG2/probe" 3000 ) \
    >"$WORK/bench.log" 2>"$WORK/bencherr.log" &
BLPID=$!
for _ in $(seq 1 80); do grep -q READY "$WORK/bencherr.log" && break; sleep 0.1; done
run_in_b() { ( echo $BASHPID > "$CG2/probe/cgroup.procs" && exec "$@" ); }
run_in_b "$WORK/burst" 50000 51950 >/dev/null 2>&1 || true
wait "$BLPID" 2>/dev/null || true

# Attach at the cgroup2 ROOT so every child cgroup is covered by the hook.
( cd "$WORK" && ./policy_v2_loader "$CG2" 5000 "$WORK/schedule" "$CG2/probe" "$CG2/expired" ) \
    >"$WORK/out.log" 2>"$WORK/err.log" &
LOADER_PID=$!
for _ in $(seq 1 80); do grep -q READY "$WORK/err.log" && break; sleep 0.1; done
grep -q READY "$WORK/err.log" || { cat "$WORK/err.log" >&2; fail "policy loader did not attach"; }

run_in() { # <cgroup-dir> <cmd...>
  local cg="$1"; shift
  ( echo $BASHPID > "$cg/cgroup.procs" && exec "$@" )
}

# (1) probe + FullPqc -> ALLOW (errno 111).
A_OUT="$(run_in "$CG2/probe" "$WORK/mx" 51111 2>&1 || true)"
# (2) expired policy object -> DENY (REASON_EXPIRED, errno 1).
E_OUT="$(run_in "$CG2/expired" "$WORK/mx" 51444 2>&1 || true)"
# (3) nopolicy cgroup -> DENY (map-miss fail-closed, errno 1).
N_OUT="$(run_in "$CG2/nopolicy" "$WORK/mx" 51333 2>&1 || true)"
# Burst from probe (FullPqc, ALLOW path) to converge the run-time accounting.
run_in "$CG2/probe" "$WORK/burst" 20000 51900 >/dev/null 2>&1 || true

# (4) wait for the scheduled FailClosed rewrite -> DENY (errno 1).
sleep 2.4
B_OUT="$(run_in "$CG2/probe" "$WORK/mx" 51222 2>&1 || true)"

wait "$LOADER_PID"; LOADER_PID=""

echo "---- structured policy object: size + memory overhead ----"
grep -E '^(STRUCT|MEM) ' "$WORK/out.log" | sed 's/^/  /'
echo "---- policy distribution (full-object update latency) ----"
grep -E '^(UPD|UPDSTATS) ' "$WORK/out.log" | sed 's/^/  /'
echo "---- kernel-side policy lookup + decision latency ----"
grep -E '^BENCHSTATS ' "$WORK/bench.log" | sed 's/^BENCHSTATS /  isolated lookup+decision: /'
grep -E '^RUNSTATS ' "$WORK/out.log" | sed 's/^RUNSTATS /  full enforcement (lookup+audit+session): /'
echo "---- session_state distributed kernel->userspace ----"
grep '^SESS ' "$WORK/out.log" | sed 's/^SESS /  live sessions: /'
echo "---- live decisions from the kernel ring buffer (sample) ----"
grep '^EVT ' "$WORK/out.log" | grep -v ':519' | head -8 | sed 's/^/  /'
echo
echo "probe   +FullPqc    connect: $A_OUT"
echo "expired +expired    connect: $E_OUT"
echo "nopolicy(none)      connect: $N_OUT"
echo "probe   +FailClosed connect: $B_OUT"

# ---- assertions: all four object-model decision paths, end-to-end ----
echo "$A_OUT" | grep -q "errno=111(" \
  && echo "  [OK] FullPqc policy object -> ALLOWED (reached net, refused)" \
  || { echo "  [FAIL] FullPqc not allowed: $A_OUT"; RC=1; }
echo "$E_OUT" | grep -q "errno=1(" \
  && echo "  [OK] expired policy object -> DENIED (REASON_EXPIRED, EPERM)" \
  || { echo "  [FAIL] expired connect not denied: $E_OUT"; RC=1; }
echo "$N_OUT" | grep -q "errno=1(" \
  && echo "  [OK] no policy object -> DENIED (map-miss fail-closed, EPERM)" \
  || { echo "  [FAIL] no-policy connect not denied: $N_OUT"; RC=1; }
echo "$B_OUT" | grep -q "errno=1(" \
  && echo "  [OK] FailClosed policy object -> DENIED (EPERM)" \
  || { echo "  [FAIL] FailClosed connect not denied: $B_OUT"; RC=1; }

grep -q "reason=expired"  "$WORK/out.log" || { echo "  [FAIL] no expired decision recorded"; RC=1; }
grep -q "reason=no-policy" "$WORK/out.log" || { echo "  [FAIL] no map-miss decision recorded"; RC=1; }
grep -q "decision=ALLOW"   "$WORK/out.log" || { echo "  [FAIL] no ALLOW decision recorded"; RC=1; }
grep -q "decision=DENY"    "$WORK/out.log" || { echo "  [FAIL] no DENY decision recorded"; RC=1; }

echo
[ "$RC" -eq 0 ] && echo "RESULT: PASS — structured policy objects stored in BPF maps, distributed from userspace, enforced by the kernel." \
               || echo "RESULT: FAIL — see rows above."
exit "$RC"
