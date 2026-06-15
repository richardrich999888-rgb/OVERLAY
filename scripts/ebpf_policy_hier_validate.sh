#!/usr/bin/env bash
#
# eBPF Policy Engine v2 — Phase 2 (Hierarchical Policy Engine) validation.
#
# Proves, by MEASUREMENT, that the kernel resolves an EFFECTIVE policy across the
# four levels Global -> Node -> Application -> Session, with conflict resolution
# = Highest Priority Wins (ties break toward the more specific level), and
# enforces it fail-closed. Each scenario is proven by a REAL connect through the
# live cgroup/connect4 hook, and the winning level is read back from the kernel
# ring buffer.
#
# Scenarios (spec tokens are L:posture:prio:expired; posture 0=FullPqc 2=FailClosed;
# L 0=global 1=node 2=app 3=session):
#   1 inherit_global          0:0:10:0                       -> ALLOW  via global
#   2 app_overrides_global    0:0:10:0 2:2:100:0             -> DENY   via app  (higher prio)
#   3 global_highest_wins     0:2:100:0 2:0:10:0             -> DENY   via global (highest prio beats more-specific)
#   4 tie_breaks_to_specific  0:0:50:0 1:0:50:0 2:2:50:0     -> DENY   via app  (equal prio, most specific)
#   5 session_highest         2:2:50:0 3:0:200:0             -> ALLOW  via session
#   6 all_expired_failclosed  0:0:100:1 2:0:100:1 3:0:100:1  -> DENY   (no applicable level -> fail closed)
#
# Requires (host): root/CAP_BPF+CAP_SYS_ADMIN, cgroup v2 + CGROUP_SOCK_ADDR,
# clang, libbpf-dev, gcc.
set -uo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"
CDIR="$HERE/ebpf/c"
WORK="$(mktemp -d)"
CG2="$WORK/cg2"
SPORT=51777
declare -i RC=0
trap 'set +e; umount "$CG2" 2>/dev/null; rm -rf "$WORK"' EXIT
fail() { echo "FATAL: $*" >&2; exit 2; }

"$CDIR/build.sh" >/dev/null || fail "eBPF build failed"
cp "$CDIR/policy_v2.bpf.o" "$CDIR/policy_v2_loader" "$WORK/"
gcc -O2 "$CDIR/testmatrix/mx_c.c" -o "$WORK/mx" 2>/dev/null || fail "need gcc"
cat > "$WORK/burst.c" <<'EOF'
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <stdlib.h>
int main(int argc,char**argv){int n=argc>1?atoi(argv[1]):10000,port=argc>2?atoi(argv[2]):51777;
 struct sockaddr_in sa;memset(&sa,0,sizeof sa);sa.sin_family=AF_INET;sa.sin_port=htons(port);
 inet_pton(AF_INET,"127.0.0.1",&sa.sin_addr);
 for(int i=0;i<n;i++){int fd=socket(AF_INET,SOCK_STREAM,0);if(fd<0)continue;
  connect(fd,(struct sockaddr*)&sa,sizeof sa);close(fd);}return 0;}
EOF
gcc -O2 "$WORK/burst.c" -o "$WORK/burst" 2>/dev/null || fail "need gcc"

mkdir -p "$CG2"
mount -t cgroup2 nodev "$CG2" 2>/dev/null || fail "cannot mount cgroup2"
mkdir -p "$CG2/probe"

run_in() { ( echo $BASHPID > "$CG2/probe/cgroup.procs" && exec "$@" ); }

echo "========== eBPF POLICY ENGINE v2 — Phase 2 (hierarchical) =========="

# ---- pass 0: inheritance-resolution latency (all four levels populated) ----
( cd "$WORK" && ./policy_v2_loader hierbench "$CG2" "$CG2/probe" "$SPORT" 3000 ) \
    >"$WORK/hb.log" 2>"$WORK/hb.err" &
HB=$!
for _ in $(seq 1 80); do grep -q READY "$WORK/hb.err" && break; sleep 0.1; done
run_in "$WORK/burst" 50000 "$SPORT" >/dev/null 2>&1 || true
wait "$HB" 2>/dev/null || true
echo "---- inheritance resolution latency (4-level resolve + decision) ----"
grep '^HIERBENCHSTATS ' "$WORK/hb.log" | sed 's/^HIERBENCHSTATS /  /'
echo

# ---- correctness scenarios ----
declare -i SC=0
scenario() { # <name> <spec> <expect_errno> <expect_level> <expect_decision>
  local name="$1" spec="$2" eerrno="$3" elevel="$4" edec="$5"
  local log="$WORK/$name.log" err="$WORK/$name.err"
  ( cd "$WORK" && ./policy_v2_loader hier "$CG2" "$CG2/probe" "$SPORT" 1200 "$spec" ) \
      >"$log" 2>"$err" &
  local pid=$!
  for _ in $(seq 1 60); do grep -q READY "$err" && break; sleep 0.1; done
  local out; out="$(run_in "$WORK/mx" "$SPORT" 2>&1 || true)"
  sleep 0.3
  wait "$pid" 2>/dev/null || true
  local prop; prop="$(grep -oE 'prop_us=[0-9]+' "$log" | head -1)"
  local evln; evln="$(grep '^EVT ' "$log" | tail -1)"
  local gotdec="?" gotlvl="?"
  echo "$evln" | grep -q "decision=DENY"  && gotdec="DENY"
  echo "$evln" | grep -q "decision=ALLOW" && gotdec="ALLOW"
  gotlvl="$(echo "$evln" | grep -oE 'level=[a-z]+' | sed 's/level=//')"
  printf "  %-24s spec=[%s]\n" "$name" "$spec"
  printf "      connect=%s  resolved level=%s decision=%s  (%s)\n" \
      "$out" "$gotlvl" "$gotdec" "$prop"
  local ok=1
  echo "$out" | grep -q "errno=$eerrno(" || ok=0
  [ "$gotlvl" = "$elevel" ] || ok=0
  [ "$gotdec" = "$edec" ] || ok=0
  if [ "$ok" = 1 ]; then echo "      [OK] expected level=$elevel decision=$edec errno=$eerrno"; SC+=1
  else echo "      [FAIL] expected level=$elevel decision=$edec errno=$eerrno"; RC=1; fi
}

scenario inherit_global         "0:0:10:0"                      111 global  ALLOW
scenario app_overrides_global   "0:0:10:0 2:2:100:0"            1   app     DENY
scenario global_highest_wins    "0:2:100:0 2:0:10:0"            1   global  DENY
scenario tie_breaks_to_specific "0:0:50:0 1:0:50:0 2:2:50:0"    1   app     DENY
scenario session_highest        "2:2:50:0 3:0:200:0"            111 session ALLOW
scenario all_expired_failclosed "0:0:100:1 2:0:100:1 3:0:100:1" 1   global  DENY

echo
echo "---- update propagation (userspace push -> live on next connect) ----"
grep -h '^HIER ' "$WORK"/*.log | grep -oE 'prop_us=[0-9]+' | sort -t= -k2 -n | tail -1 \
    | sed 's/^/  max push-to-kernel latency: /'
echo "  (the change is enforced on the very next connect — the kernel reads live map state per packet)"
echo
[ "$SC" -eq 6 ] && [ "$RC" -eq 0 ] \
  && echo "RESULT: PASS — 6/6 hierarchy scenarios correct; highest-priority-wins + specificity tiebreak + fail-closed proven." \
  || echo "RESULT: FAIL ($SC/6 scenarios correct) — see rows above."
exit "$RC"
