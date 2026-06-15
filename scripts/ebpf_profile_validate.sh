#!/usr/bin/env bash
#
# eBPF Policy Engine v2 — Phase 6 (Defence Policy Profiles) validation.
#
# Proves the three deployable profiles enforce their intended behaviour, by REAL
# connects, and measures profile application + switch latency:
#
#   Strategic Command : FullPqcOnly + HardwareKeyRequired + FailClosed (no fallback)
#   Tactical Comms    : FullPqc + FallbackAllowed
#   Legacy Migration  : HybridOnly + controlled fallback
#
# Normal posture (FullPqc): every profile ALLOWS. Degraded posture
# (EncryptedFallback): Strategic FAILS CLOSED (no fallback) while Tactical/Legacy
# keep the encrypted link up — the assurance↔resilience distinction.
#
# Requires (host): root, cgroup v2 + CGROUP_SOCK_ADDR, clang, libbpf-dev, gcc.
set -uo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"
CDIR="$HERE/ebpf/c"
WORK="$(mktemp -d)"
CG2="$WORK/cg2"
SPORT=52111
declare -i RC=0
trap 'set +e; umount "$CG2" 2>/dev/null; rm -rf "$WORK"' EXIT
fail() { echo "FATAL: $*" >&2; exit 2; }

"$CDIR/build.sh" >/dev/null || fail "eBPF build failed"
cp "$CDIR/policy_v2.bpf.o" "$CDIR/policy_v2_loader" "$WORK/"
gcc -O2 "$CDIR/testmatrix/mx_c.c" -o "$WORK/mx" 2>/dev/null || fail "need gcc"

mkdir -p "$CG2"
mount -t cgroup2 nodev "$CG2" 2>/dev/null || fail "cannot mount cgroup2"
mkdir -p "$CG2/probe"
run_in() { ( echo $BASHPID > "$CG2/probe/cgroup.procs" && exec "$@" ); }
errno_of() { echo "$1" | grep -oE 'errno=[0-9]+' | head -1 | sed 's/errno=//'; }

echo "========== eBPF POLICY ENGINE v2 — Phase 6 (defence profiles) =========="
declare -i SC=0
prof() { # <name> <degraded> <expect_errno> <desc>
  local name="$1" deg="$2" eerrno="$3" desc="$4"
  local log="$WORK/$name$deg.log" err="$WORK/$name$deg.err"
  ( cd "$WORK" && ./policy_v2_loader profile "$CG2" "$CG2/probe" "$SPORT" 1200 "$name" "$deg" ) \
      >"$log" 2>"$err" &
  local pid=$!
  for _ in $(seq 1 60); do grep -q READY "$err" && break; sleep 0.1; done
  local out; out="$(run_in "$WORK/mx" "$SPORT" 2>&1 || true)"
  sleep 0.2
  wait "$pid" 2>/dev/null || true
  local apply; apply="$(grep -oE 'apply_us=[0-9]+' "$log" | head -1)"
  printf "  %-10s %-9s %-28s connect=%s  (%s)\n" \
      "$name" "$([ "$deg" = 1 ] && echo degraded || echo normal)" "$desc" "$out" "$apply"
  if [ "$(errno_of "$out")" = "$eerrno" ]; then
    echo "      [OK] expected errno=$eerrno"; SC+=1
  else
    echo "      [FAIL] expected errno=$eerrno, got $(errno_of "$out")"; RC=1
  fi
}

echo "-- normal posture (FullPqc): all profiles allow --"
prof strategic 0 111 "FullPqcOnly+HwKey"
prof tactical  0 111 "FullPqc+FallbackAllowed"
prof legacy    0 111 "HybridOnly+ctrl-fallback"
echo "-- degraded posture (EncryptedFallback): Strategic fails closed --"
prof strategic 1 1   "no fallback -> FAIL CLOSED"
prof tactical  1 111 "fallback keeps link up"
prof legacy    1 111 "controlled fallback up"

echo
echo "-- profile application & switch latency --"
( cd "$WORK" && ./policy_v2_loader profileswitch "$CG2" "$CG2/probe" "$SPORT" 3000 ) \
    >"$WORK/sw.log" 2>"$WORK/sw.err" || true
grep '^PROFILESWITCH ' "$WORK/sw.log" | sed 's/^PROFILESWITCH /  /'

echo
[ "$SC" -eq 6 ] && [ "$RC" -eq 0 ] \
  && echo "RESULT: PASS — 3 deployable profiles enforce assurance↔resilience correctly; Strategic fails closed, Tactical/Legacy stay up (encrypted); switch latency measured." \
  || echo "RESULT: FAIL ($SC/6 profile checks) — see rows above."
exit "$RC"
