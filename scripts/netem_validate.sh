#!/usr/bin/env bash
#
# Battlefield resilience — REAL `tc netem` validation harness.
#
# Prefers real netem. On a netem-capable host it builds a veth pair across two
# network namespaces, applies `netem loss/delay/reorder` at 10/20/30/45 %, and
# confirms the impairment (ping loss/RTT). On a host WITHOUT the qdisc layer (as
# in the CI sandbox), it prints the precise reason and the host-side plan, and
# exits 0 (documented limitation, not a failure).
#
# Requires (capable host): root/CAP_NET_ADMIN, iproute2 with `sch_netem`.
set -uo pipefail

NS_A=syn_neta NS_B=syn_netb
cleanup() {
  ip netns del "$NS_A" 2>/dev/null
  ip netns del "$NS_B" 2>/dev/null
  ip link del syn_veth0 2>/dev/null
}
trap cleanup EXIT

echo "==== tc netem capability probe ===="
if ! command -v tc >/dev/null; then
  echo "RESULT: tc (iproute2) not installed."
  echo "  install: apt-get install -y iproute2"
  exit 0
fi

# Probe whether the netem qdisc exists at all.
ip link add syn_probe0 type veth peer name syn_probe1 2>/dev/null || true
if tc qdisc add dev syn_probe0 root netem loss 10% 2>/tmp/netem_probe.err; then
  tc qdisc del dev syn_probe0 root 2>/dev/null
  ip link del syn_probe0 2>/dev/null
  NETEM_OK=1
else
  REASON="$(tr -d '\n' </tmp/netem_probe.err)"
  ip link del syn_probe0 2>/dev/null
  NETEM_OK=0
fi

if [ "$NETEM_OK" -ne 1 ]; then
  # Compute the diagnosis (qdisc availability + module dir) into variables.
  QPROBE=""
  for q in netem tbf prio htb; do
    ip link add zz0 type veth peer name zz1 2>/dev/null
    if tc qdisc add dev zz0 root "$q" >/dev/null 2>&1; then QPROBE+="$q=yes "; else QPROBE+="$q=NO "; fi
    tc qdisc del dev zz0 root 2>/dev/null; ip link del zz0 2>/dev/null
  done
  MODDIR="$(ls "/lib/modules/$(uname -r)/kernel/net/sched/" 2>/dev/null | tr '\n' ' ')"
  [ -z "$MODDIR" ] && MODDIR="absent (qdiscs would need to be built-in)"

  echo "RESULT: REAL tc netem is NOT AVAILABLE on this host."
  echo "  reason : ${REASON:-qdisc kind unknown}"
  echo "  kernel : $(uname -r)"
  echo "  qdiscs : $QPROBE"
  echo "  sched module dir: $MODDIR"
  cat <<'PLAN'

  HOST-SIDE VALIDATION PLAN (run on a netem-capable Linux host):
    for L in 10 20 30 45; do
      ip netns add A; ip netns add B
      ip link add vA type veth peer name vB
      ip link set vA netns A; ip link set vB netns B
      ip -n A addr add 10.9.0.1/24 dev vA; ip -n A link set vA up; ip -n A link set lo up
      ip -n B addr add 10.9.0.2/24 dev vB; ip -n B link set vB up; ip -n B link set lo up
      # apply netem on BOTH directions (loss + jitter + reorder)
      ip netns exec A tc qdisc add dev vA root netem loss ${L}% delay 40ms 15ms reorder 25% 50%
      ip netns exec B tc qdisc add dev vB root netem loss ${L}% delay 40ms 15ms reorder 25% 50%
      ip netns exec A ping -c 200 -i 0.01 10.9.0.2 | tail -3      # confirm loss% + rtt
      # drive the REAL daemon across the impaired link:
      #   B: SYNTRIASS_OVERSOCKET_LISTEN=10.9.0.2:8443 <identity env> daemon &
      #   A: client connects to 10.9.0.2:8443 -> record handshake success-rate/latency
      ip netns del A; ip netns del B
    done
  The metrics the userspace counterpart already measures
  (tests/battlefield_resilience.rs) would then be [measured: kernel netem]
  rather than [measured: userspace model]. Re-run THIS script there to populate
  docs/NETEM_RESULTS.md with the real ladder.
PLAN
  exit 0
fi

# ---- netem IS available: run the real ladder ----
echo "netem AVAILABLE — running the real loss ladder"
ip netns add "$NS_A"; ip netns add "$NS_B"
ip link add vA type veth peer name vB
ip link set vA netns "$NS_A"; ip link set vB netns "$NS_B"
ip -n "$NS_A" addr add 10.9.0.1/24 dev vA; ip -n "$NS_A" link set vA up; ip -n "$NS_A" link set lo up
ip -n "$NS_B" addr add 10.9.0.2/24 dev vB; ip -n "$NS_B" link set vB up; ip -n "$NS_B" link set lo up
printf "%5s %10s %10s\n" "loss%" "ping_loss" "rtt_avg_ms"
for L in 10 20 30 45; do
  ip netns exec "$NS_A" tc qdisc replace dev vA root netem loss "${L}%" delay 40ms 15ms reorder 25% 50% 2>/dev/null
  ip netns exec "$NS_B" tc qdisc replace dev vB root netem loss "${L}%" delay 40ms 15ms reorder 25% 50% 2>/dev/null
  out="$(ip netns exec "$NS_A" ping -c 200 -i 0.01 -W 1 10.9.0.2 2>/dev/null)"
  ploss="$(echo "$out" | grep -oE '[0-9.]+% packet loss' | head -1)"
  rtt="$(echo "$out" | grep -oE 'rtt.*= [0-9./]+' | awk -F'/' '{print $5}')"
  printf "%5s %10s %10s\n" "$L" "${ploss:-?}" "${rtt:-?}"
done
echo "RESULT: real netem ladder measured (record above as docs/NETEM_RESULTS.md)."
