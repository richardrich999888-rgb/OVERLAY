# Loader Fail-Closed Review (HI-2)

**Internal Security Hardening and Pre-Audit Remediation.**

## Objective
Ensure that failure of the eBPF policy loader / control-plane daemon never creates
a policy bypass (egress permitted unencrypted).

## Lifecycle analysis
| Path | Current behaviour | Risk |
|---|---|---|
| Loader running, attached | enforces fail-closed from live map state (deny on map-miss / FailClosed / quarantine) | OK |
| **Loader crash / kill / OOM** | the `cgroup/connect4` program **detaches**; `connect` then defaults to **allow** | **fail-OPEN** |
| Loader restart | re-attaches; gap between death and restart is unprotected | window of fail-open |
| Boot, before daemon starts | no program attached; egress permitted | fail-open until daemon up |

The kernel enforcement is therefore **liveness-dependent**: it holds only while a
program is attached. The validation harness loaders intentionally detach on exit.

## Remediation design ([design] for the production loader)
1. **Pin the `bpf_link`** (`bpf_link__pin` / `LIBBPF_PIN_BY_NAME` to bpffs) so the
   attachment **survives loader process death** — the program keeps enforcing even
   if the userspace control plane crashes. The daemon re-opens the pinned link on
   restart rather than re-attaching.
2. **Boot-time default-deny baseline**: at cgroup setup, before the daemon starts,
   install a program with an empty `policy_table` and no FullPqc posture, so the
   default is **FailClosed** (deny) — egress is closed until the daemon explicitly
   asserts a healthy posture. Combined with pinning, a crash leaves the last-known
   policy (or default-deny), never open.
3. **Supervisor**: run the daemon under `systemd` with `Restart=always` and a
   watchdog (`WatchdogSec`); on missed heartbeats, systemd restarts it while the
   pinned link continues to enforce.
4. **Health-gated posture**: the daemon pushes a permissive posture only while it
   is healthy; loss of health reverts the map to FailClosed (the kinetic
   supervisor already models this — wire it to the map on the BPF host).

## Validation plan ([design] — needs root + bpffs on a live kernel)
- Pin the link, `kill -9` the loader, confirm a `connect` from the cgroup is still
  denied (program survived).
- Boot sequence: confirm egress is denied before the daemon starts.
- Restart race: kill+restart under load; confirm no fail-open window (pinned link
  never detaches).

## Status
- `[design]`: link pinning, default-deny baseline, systemd supervision, health-gated
  posture, and the live-kernel validation. The analysis and the concrete mechanism
  are specified; implementation + validation require the production loader and a
  live kernel and are the deployment-hardening step before any pilot.
- The **userspace** overlay already fails closed on daemon death for interposed
  flows; this review concerns the **kernel** layer's fail-open-on-detach.
