#!/usr/bin/env bash
#
# eBPF Policy Engine v2 — Phase 4 (Quarantine Engine) validation.
#
# Proves, by MEASUREMENT, that a quarantined cgroup is denied ALL egress
# (highest-priority deny, overriding policy), for the three quarantine kinds, and
# that recovery happens correctly:
#   Temporary  : auto-releases when the duration elapses
#   AutoExpiry : auto-releases at the deadline
#   Permanent  : releases ONLY on manual delete
# Each step is a REAL connect through the live hook. Propagation (userspace push
# -> enforced), enforcement (kernel run-time), and recovery latency are measured.
#
# Requires (host): root, cgroup v2 + CGROUP_SOCK_ADDR, clang, libbpf-dev, gcc.
set -uo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"
CDIR="$HERE/ebpf/c"
WORK="$(mktemp -d)"
CG2="$WORK/cg2"
SPORT=51999
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
int main(int argc,char**argv){int n=argc>1?atoi(argv[1]):10000,port=argc>2?atoi(argv[2]):51999;
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
errno_of() { echo "$1" | grep -oE 'errno=[0-9]+' | head -1 | sed 's/errno=//'; }

echo "============ eBPF POLICY ENGINE v2 — Phase 4 (quarantine) ============"

# ---- pass 0: enforcement latency under an active (permanent) quarantine ----
( cd "$WORK" && ./policy_v2_loader quarbench "$CG2" "$CG2/probe" "$SPORT" 3000 ) \
    >"$WORK/qb.log" 2>"$WORK/qb.err" &
QB=$!
for _ in $(seq 1 80); do grep -q READY "$WORK/qb.err" && break; sleep 0.1; done
run_in "$WORK/burst" 50000 "$SPORT" >/dev/null 2>&1 || true
wait "$QB" 2>/dev/null || true
echo "---- quarantine enforcement latency (quarantine check + deny) ----"
grep '^QUARBENCHSTATS ' "$WORK/qb.log" | sed 's/^QUARBENCHSTATS /  /'
echo

# ---- recovery scenario: <name> <kind> <dur_ms> <rel_ms> ----
# Connect timeline (elapsed ms): t1=200 (expect DENY), t2=900 (expect ALLOW after recovery).
declare -i SC=0
recover() { # <name> <kind> <dur_ms> <rel_ms> <recovery_desc>
  local name="$1" kind="$2" dur="$3" rel="$4" desc="$5"
  local log="$WORK/$name.log" err="$WORK/$name.err"
  ( cd "$WORK" && ./policy_v2_loader quar "$CG2" "$CG2/probe" "$SPORT" 1300 "$kind" "$dur" "$rel" ) \
      >"$log" 2>"$err" &
  local pid=$!
  for _ in $(seq 1 60); do grep -q READY "$err" && break; sleep 0.1; done
  local tstart; tstart=$(date +%s%3N)
  sleep 0.2
  local d1; d1="$(run_in "$WORK/mx" "$SPORT" 2>&1 || true)"   # ~200ms: quarantined
  sleep 0.7
  local d2; d2="$(run_in "$WORK/mx" "$SPORT" 2>&1 || true)"   # ~900ms: recovered?
  wait "$pid" 2>/dev/null || true
  local prop; prop="$(grep -oE 'prop_us=[0-9]+' "$log" | head -1)"
  local qrel; qrel="$(grep -oE 'QREL us=[0-9]+' "$log" | head -1)"
  printf "  %-12s kind=%s dur=%sms rel=%sms  (%s)\n" "$name" "$kind" "$dur" "$rel" "$desc"
  printf "      t~200ms: %s\n      t~900ms: %s\n" "$d1" "$d2"
  printf "      propagation %s  %s\n" "$prop" "${qrel:-(no manual release)}"
  local e1 e2; e1="$(errno_of "$d1")"; e2="$(errno_of "$d2")"
  # expect: denied (1) while quarantined, allowed (111 = reached net) after recovery
  if [ "$e1" = "1" ] && [ "$e2" = "111" ]; then
    echo "      [OK] quarantined -> DENY, recovered -> ALLOW"; SC+=1
  else
    echo "      [FAIL] expected DENY(1) then ALLOW(111), got $e1 then $e2"; RC=1
  fi
  grep -q "reason=quarantine" "$log" || { echo "      [FAIL] no quarantine decision recorded"; RC=1; }
}

# Temporary: 500ms duration, no manual release -> auto-releases by t~900ms.
recover temporary  0 500 -1 "auto-release at duration"
# AutoExpiry: 500ms deadline, no manual release -> auto-releases by t~900ms.
recover autoexpiry 2 500 -1 "auto-release at deadline"
# Permanent: no expiry (dur=0), manual release at 600ms -> released by t~900ms.
recover permanent  1 0  600 "manual release only"

# Permanent WITHOUT release must STAY denied (sanity: no auto-recovery).
echo "  permanent-no-release kind=1 dur=0 rel=none  (must stay quarantined)"
( cd "$WORK" && ./policy_v2_loader quar "$CG2" "$CG2/probe" "$SPORT" 1000 1 0 -1 ) \
    >"$WORK/pnr.log" 2>"$WORK/pnr.err" &
PNR=$!
for _ in $(seq 1 60); do grep -q READY "$WORK/pnr.err" && break; sleep 0.1; done
sleep 0.2; PN1="$(run_in "$WORK/mx" "$SPORT" 2>&1 || true)"
sleep 0.6; PN2="$(run_in "$WORK/mx" "$SPORT" 2>&1 || true)"
wait "$PNR" 2>/dev/null || true
if [ "$(errno_of "$PN1")" = "1" ] && [ "$(errno_of "$PN2")" = "1" ]; then
  echo "      [OK] permanent quarantine stayed DENY with no manual release"; SC+=1
else
  echo "      [FAIL] permanent quarantine should stay denied: $PN1 / $PN2"; RC=1
fi

echo
[ "$SC" -eq 4 ] && [ "$RC" -eq 0 ] \
  && echo "RESULT: PASS — quarantine denies all egress; Temporary/AutoExpiry auto-release, Permanent holds until manual release." \
  || echo "RESULT: FAIL ($SC/4 checks correct) — see rows above."
exit "$RC"
