#!/usr/bin/env bash
#
# eBPF Policy Engine v2 — Phase 3 (Cryptographic Policy Enforcement) — kernel half.
#
# The kernel data plane enforces the crypto consequence it can observe at connect
# time: whether a fallback (EncryptedFallback, posture=1) connection is permitted,
# from the policy object's crypto_flags. (Suite / hardware-key / classical-vs-
# symmetric requirements are enforced at handshake time by the daemon — see
# src/crypto/crypto_policy.rs and tests/crypto_policy_tests.rs.)
#
# Each scenario is proven by a REAL connect. crypto_flags bits:
#   FULL_PQC_ONLY=1  HYBRID_ONLY=2  FALLBACK_ALLOWED=4  HARDWARE_KEY_REQ=8  NO_CLASSICAL_FB=16
# Spec tokens are L:posture:prio:expired:crypto (posture 0=FullPqc 1=Fallback 2=FailClosed).
#
# Requires (host): root, cgroup v2 + CGROUP_SOCK_ADDR, clang, libbpf-dev, gcc.
set -uo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"
CDIR="$HERE/ebpf/c"
WORK="$(mktemp -d)"
CG2="$WORK/cg2"
SPORT=51888
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

echo "======= eBPF POLICY ENGINE v2 — Phase 3 (crypto enforcement, kernel) ======="
declare -i SC=0
scenario() { # <name> <spec> <expect_errno> <expect_reason> <expect_decision>
  local name="$1" spec="$2" eerrno="$3" ereason="$4" edec="$5"
  local log="$WORK/$name.log" err="$WORK/$name.err"
  ( cd "$WORK" && ./policy_v2_loader hier "$CG2" "$CG2/probe" "$SPORT" 1200 "$spec" ) \
      >"$log" 2>"$err" &
  local pid=$!
  for _ in $(seq 1 60); do grep -q READY "$err" && break; sleep 0.1; done
  local out; out="$(run_in "$WORK/mx" "$SPORT" 2>&1 || true)"
  sleep 0.3
  wait "$pid" 2>/dev/null || true
  local evln; evln="$(grep '^EVT ' "$log" | tail -1)"
  local gotdec="?" gotreason="?"
  echo "$evln" | grep -q "decision=DENY"  && gotdec="DENY"
  echo "$evln" | grep -q "decision=ALLOW" && gotdec="ALLOW"
  gotreason="$(echo "$evln" | grep -oE 'reason=[a-z-]+' | sed 's/reason=//')"
  printf "  %-26s spec=[%s]\n" "$name" "$spec"
  printf "      connect=%s  decision=%s reason=%s\n" "$out" "$gotdec" "$gotreason"
  local ok=1
  echo "$out" | grep -q "errno=$eerrno(" || ok=0
  [ "$gotdec" = "$edec" ] || ok=0
  [ "$gotreason" = "$ereason" ] || ok=0
  if [ "$ok" = 1 ]; then echo "      [OK] expected decision=$edec reason=$ereason errno=$eerrno"; SC+=1
  else echo "      [FAIL] expected decision=$edec reason=$ereason errno=$eerrno"; RC=1; fi
}

# posture 1 = EncryptedFallback; posture 0 = FullPqc.
scenario fallback_allowed        "2:1:100:0:4"  111 ok                 ALLOW
scenario fallback_denied_no_flag "2:1:100:0:0"  1   crypto-policy      DENY
scenario full_pqc_only_no_fb     "2:1:100:0:19" 1   crypto-policy      DENY
scenario full_pqc_posture_ok     "2:0:100:0:19" 111 ok                 ALLOW
scenario no_classical_symmetric  "2:1:100:0:20" 111 ok                 ALLOW

echo
[ "$SC" -eq 5 ] && [ "$RC" -eq 0 ] \
  && echo "RESULT: PASS — kernel enforces crypto fallback policy from crypto_flags; FullPqcOnly denies fallback, FallbackAllowed permits it." \
  || echo "RESULT: FAIL ($SC/5 scenarios correct) — see rows above."
exit "$RC"
