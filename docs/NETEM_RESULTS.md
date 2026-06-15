# netem Results

Tags per `BATTLEFIELD_RESILIENCE.md`. This document records the **real `tc netem`
attempt**, why it could not run here, and the exact host-side plan to produce the
real netem ladder elsewhere.

## 1. Attempt & result — **[measured]** (`scripts/netem_validate.sh`)

`bash scripts/netem_validate.sh` on this host produced (captured in
`docs/NETEM_PROBE_OUTPUT.txt`):

```
RESULT: REAL tc netem is NOT AVAILABLE on this host.
  reason : Error: Specified qdisc kind is unknown.
  kernel : 6.18.5
  qdiscs : netem=NO tbf=NO prio=NO htb=NO
  sched module dir: absent (qdiscs would need to be built-in)
```

`iproute2` (`tc`/`ip`) installs and `ip netns`/`veth` work, but the kernel
exposes **no traffic-control qdisc scheduler** — `netem`, `tbf`, `prio`, `htb`
all report "qdisc kind unknown", and there is no `/lib/modules/<ver>/kernel/net/sched/`
directory, so the qdiscs are neither built-in nor loadable. `modprobe` is also
absent. **Real netem cannot be exercised in this environment** — a hard, verified
limitation, not a code gap.

## 2. What was measured instead (and how it maps to netem)

The userspace impairment model (`tests/battlefield_resilience.rs`,
`BATTLEFIELD_RESILIENCE.md §1–§2`) applies loss / bounded reorder / jitter / replay
to the **real bytes of the real handshake + record layer**. It is faithful to a
datagram overlay's loss handling; what it does **not** capture (and netem would)
is the kernel **TCP retransmit timing** under loss. The metrics that are
host-independent — delivery, replay-rejection, success-rate floor, leaks = 0 —
are already `[measured]`; the timing under TCP retransmit is the `[design]` gap.

## 3. Host-side validation plan (run on a netem-capable host)

Requires: a Linux host with `sch_netem` (most distro kernels), root/`CAP_NET_ADMIN`,
`iproute2`. `scripts/netem_validate.sh` runs this automatically when netem is
present (it builds the namespaces, applies the ladder, and confirms loss/RTT with
`ping`). The core is:

```bash
for L in 10 20 30 45; do
  ip netns add A; ip netns add B
  ip link add vA type veth peer name vB
  ip link set vA netns A; ip link set vB netns B
  ip -n A addr add 10.9.0.1/24 dev vA; ip -n A link set vA up; ip -n A link set lo up
  ip -n B addr add 10.9.0.2/24 dev vB; ip -n B link set vB up; ip -n B link set lo up
  # impair BOTH directions: loss + jitter + reorder
  ip netns exec A tc qdisc add dev vA root netem loss ${L}% delay 40ms 15ms reorder 25% 50%
  ip netns exec B tc qdisc add dev vB root netem loss ${L}% delay 40ms 15ms reorder 25% 50%
  ip netns exec A ping -c 200 -i 0.01 10.9.0.2 | tail -3          # confirm loss% + RTT
  # drive the REAL daemon across the impaired link:
  #   B: SYNTRIASS_OVERSOCKET_LISTEN=10.9.0.2:8443 <identity env> daemon &
  #   A: client connects to 10.9.0.2:8443  -> record handshake success-rate + latency
  ip netns del A; ip netns del B
done
```

Recommended netem parameters per scenario:

| Scenario | netem clause |
|---|---|
| 10/20/30/45 % loss ladder | `loss <L>%` |
| jitter / satellite | `delay 40ms 15ms distribution normal` |
| reordering | `reorder 25% 50%` |
| intermittent connectivity | toggle `tc qdisc add … netem loss 100%` ⇄ `del` on an interval |
| congestion / bandwidth | add `tbf rate 64kbit burst 8kb latency 400ms` (or `netem rate`) |
| corruption | `corrupt 1%` |

## 4. Expected netem-vs-userspace delta

On a netem host, re-running the daemon across the impaired link upgrades:

| Metric | here (userspace) | on a netem host |
|---|---|---|
| record delivery / replay-rejection / leaks=0 | [measured] | [measured] (same, confirmed over the wire) |
| handshake success rate | [measured: floor, no retransmit] | [measured: with TCP retransmit] (expected higher) |
| latency under loss | [measured: model] | [measured: real RTT + retransmit] |

Re-run `scripts/netem_validate.sh` on that host and paste its output here to make
this section `[measured: kernel netem]`.
