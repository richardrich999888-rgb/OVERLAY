# Pilot Readiness Reassessment

**Internal Security Hardening and Pre-Audit Remediation.** First-party opinion;
not an authority approval.

## Score: 5 / 10 (was 4 / 10)

| Pilot type | Verdict |
|---|---|
| Operational pilot with real/sensitive traffic | **NOT READY** — deployment-level CR-3/CR-4 wiring + HI-1/HI-2 still gate it |
| Controlled lab / non-production pilot | **READY (improved)** — the crypto-break (CR-2) is eliminated and the air-gap/supply-chain cores are tested |

## What changed since the first assessment
- **CR-2 fork→nonce reuse: CLOSED** — the catastrophic GCM break that was the #1
  pilot gate is eliminated and proven (real-fork tests demonstrate the averted
  reuse). This is the single biggest improvement.
- **CR-3 air-gap MITM / CR-4 supply-chain RCE: tested cores** — the secure
  mechanism (hybrid-signed bundles, fail-closed verification) exists and passes
  adversarial tests. **But** the shipped `airgap.sh`/`install.sh` do not yet call
  it, so the *deployment path* is not yet secured — the operational gate stands
  until wired.
- **IPv6**: `connect6` added (compile-verified), narrowing HI-1.

## Gating items remaining for an operational pilot
1. Wire CR-3 verification into `airgap.sh`/`import-peer`/`apply-policy-bundle`.
2. Wire CR-4 verification into `install.sh`/`package.sh`.
3. Complete HI-1: live-validate `connect6`, add UDP `sendmsg4/6`, default-deny
   unknown families.
4. Close HI-2: pin the bpf_link + boot default-deny + supervision.
5. Low-effort deploy hardening HI-6..HI-9 (private-seed temp leaks, inventory
   injection).

## Conditional-lab-pilot guardrails (unchanged, still apply)
Isolated network; no traffic of value; trusted local provisioning; locally-built
package; IPv4-TCP only (or treat IPv6/UDP as unprotected); run the eBPF loader
under a supervisor.

## Path to "pilot ready" (target ≥ 7/10)
Close items 1–4 above with their validation gates, then re-score. CR-2 closure
already removed the hardest gate; the rest is integration + kernel work, not new
cryptography.

## TRL impact
No change to functional TRL 5; pilot-deployment readiness moved from "blocked by a
crypto break" to "blocked by integration/kernel hardening" — a materially better
position.
