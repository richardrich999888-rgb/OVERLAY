#!/usr/bin/env bash
#
# Production eBPF policy/state layer — validation (Phase 3).
#
# Proves, by MEASUREMENT, that the kernel `cgroup/connect4` policy program
# enforces egress decisions from LIVE map state that userspace distributes:
#   - userspace pushes the operational posture into the operation_mode map
#     (posture distribution) and the update latency is measured;
#   - in FullPqc/EncryptedFallback the kernel ALLOWS and records per-flow
#     session_state (kernel->userspace distribution);
#   - in FailClosed the kernel DENIES every connect (EPERM) — the fail-closed
#     transition.
#
# Requires (host, not the default sandbox): root/CAP_BPF+CAP_SYS_ADMIN, kernel
# with cgroup v2 + CGROUP_SOCK_ADDR, clang, libbpf-dev, gcc.
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
cp "$CDIR/policy.bpf.o" "$CDIR/policy_loader" "$WORK/"
gcc -O2 "$CDIR/testmatrix/mx_c.c" -o "$WORK/mx" 2>/dev/null || fail "need gcc for the connect probe"

mkdir -p "$CG2"
mount -t cgroup2 nodev "$CG2" 2>/dev/null || fail "cannot mount cgroup2 (need CAP_SYS_ADMIN)"
mkdir -p "$CG2/probe"

# Schedule: FullPqc (0) at t=0, then FailClosed (2) at t=2000 ms.
printf '0 0\n2000 2\n' > "$WORK/schedule"

echo "================ eBPF POLICY/STATE LAYER (measured) ================"
( cd "$WORK" && ./policy_loader "$CG2/probe" 4000 "$WORK/schedule" ) >"$WORK/out.log" 2>"$WORK/err.log" &
LOADER_PID=$!
for _ in $(seq 1 60); do grep -q READY "$WORK/err.log" && break; sleep 0.1; done
grep -q READY "$WORK/err.log" || { cat "$WORK/err.log" >&2; fail "policy loader did not attach"; }

# Join the cgroup so our connects hit the policy hook.
echo $$ > "$CG2/probe/cgroup.procs" || fail "cannot join cgroup"

# t~700ms: posture is FullPqc -> connect must be ALLOWED (reaches the network;
# refused since nothing listens => errno 111, NOT denied).
sleep 0.7
A_OUT="$("$WORK/mx" 51111 2>&1 || true)"
# wait for FailClosed transition (scheduled at 2000ms)
sleep 1.8
# t~2500ms: posture is FailClosed -> connect must be DENIED (errno 1 = EPERM).
B_OUT="$("$WORK/mx" 51222 2>&1 || true)"

echo $$ > "$CG2/cgroup.procs" 2>/dev/null || true
wait "$LOADER_PID"; LOADER_PID=""

echo "---- posture distribution (map update latency) ----"
grep '^UPD ' "$WORK/out.log" | sed 's/^/  /'
echo "---- enforcement decisions (from the kernel ring buffer) ----"
grep '^EVT ' "$WORK/out.log" | sed 's/^/  /'
echo "---- session_state entries distributed kernel->userspace ----"
grep '^SESS ' "$WORK/out.log" | sed 's/^SESS /  live sessions: /'
echo
echo "FullPqc connect result : $A_OUT"
echo "FailClosed connect result: $B_OUT"

# Assertions.
if echo "$A_OUT" | grep -q "errno=111("; then
  echo "  [OK] FullPqc -> ALLOWED (reached network, connection refused)"
else echo "  [FAIL] FullPqc connect not allowed: $A_OUT"; RC=1; fi
if echo "$B_OUT" | grep -q "errno=1("; then
  echo "  [OK] FailClosed -> DENIED (EPERM): fail-closed transition enforced by map state"
else echo "  [FAIL] FailClosed connect not denied: $B_OUT"; RC=1; fi
grep -q "decision=ALLOW" "$WORK/out.log" || { echo "  [FAIL] no ALLOW decision recorded"; RC=1; }
grep -q "decision=DENY"  "$WORK/out.log" || { echo "  [FAIL] no DENY decision recorded"; RC=1; }

echo
[ "$RC" -eq 0 ] && echo "RESULT: PASS — kernel enforces live posture from map state; fail-closed transition works." \
               || echo "RESULT: FAIL — see rows above."
exit "$RC"
