# Egress Coverage Review (HI-1)

**Internal Security Hardening and Pre-Audit Remediation.**

## Objective
Remove protocol-bypass opportunities in the kernel eBPF enforcement, which the
pre-audit found covered only IPv4 TCP `connect`.

## Coverage matrix
| Egress path | Hook | Status |
|---|---|---|
| IPv4 TCP connect | `cgroup/connect4` (`syntriass_policy_v2`, `_hier`) | **[implemented] [tested]** — real-connect validators (`scripts/ebpf_policy_v2_validate.sh`, etc.), deny=EPERM |
| **IPv6 TCP connect** | `cgroup/connect6` (`syntriass_policy_hier6`) | **[implemented]** (compile-verified, BPF target) — added this pass; **attach/enforcement on a live kernel = [design]** |
| **UDP IPv4** (`sendmsg4`) | `cgroup/sendmsg4` | **[design]** — not yet implemented |
| **UDP IPv6** (`sendmsg6`) | `cgroup/sendmsg6` | **[design]** — not yet implemented |
| Connected-UDP / `recvmsg` ingress | — | out of scope (egress policy) |
| Raw sockets / AF_PACKET | — | requires `CAP_NET_RAW`; out of cgroup-sockaddr scope; covered by host hardening, not this engine |

## What was implemented this pass
`cgroup/connect6` (`ebpf/c/policy_v2.bpf.c`) mirrors the hierarchical decision.
The policy resolver (`syntriass_resolve`) and the quarantine check are
**cgroup-keyed and therefore address-family independent** — only the per-flow
`session_state` key uses the destination, so the IPv6 program derives a flow key
from the low 64 bits of the v6 address. The decision (quarantine → resolve →
posture → crypto-fallback gate) is identical to `connect4`. It compiles cleanly
for the BPF target; loading/attaching `connect6` and running a real IPv6 connect
under a FailClosed posture (deny = EPERM) is the validation step that needs a live
kernel + cgroup, deferred as `[design]`.

## Remaining gaps and kernel limitations
- **UDP** requires `cgroup/sendmsg4` and `cgroup/sendmsg6` programs (the
  `bpf_sock_addr` context differs; for unconnected UDP the hook fires per
  `sendmsg`). Mirror the same cgroup-keyed decision; the per-datagram cost is
  higher than per-connect. **[design]**.
- **Default-deny for unknown families**: consider a `cgroup/sock_create` hook (or
  a connect4/connect6 pair plus a sendmsg pair) so any egress not matched by a
  policy program is denied. Currently an unhooked family is permitted (fail-open
  for that family).
- **The kernel hook gates connection establishment, not encryption** (E-3 in the
  pre-audit). A kernel-ALLOWED connection is encrypted only if the userspace
  interceptor wraps it. Complete egress coverage closes the *bypass* gap but does
  not by itself make the kernel the encryption authority — that decoupling must be
  stated in the threat model.

## Recommendation
Before pilot: implement + live-validate `connect6` and `sendmsg4/6`, add a
default-deny-unknown-family baseline, and document the kernel-gates-establishment
vs userspace-encrypts split explicitly. Until then, restrict pilot applications
to IPv4 TCP or treat IPv6/UDP as unprotected.
