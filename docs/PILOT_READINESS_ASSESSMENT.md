# SYNTRIASS Overlay — Pilot Readiness Assessment

> **Internal Security Review / Pre-Audit Assessment.** First-party opinion. Not a
> certification or accreditation. "Ready" here means *the reviewer's judgement of
> whether a defence pilot should carry real traffic*, not an authority's approval.

## Verdict

| Pilot type | Verdict |
|---|---|
| **Operational pilot with real/sensitive traffic** | **NOT READY** — blocked by 3 open Critical findings |
| **Controlled lab / non-production pilot** (synthetic traffic, isolated network, no real keys of value) | **CONDITIONAL** — acceptable to exercise functionality and gather TRL-6 evidence, provided it carries no traffic whose compromise matters and the air-gap/supply-chain path is not trusted |

## Pilot Readiness Score: **4 / 10**

Rationale: the cryptographic core and the functional TRL-5 evidence are strong
(raising the score above the floor), but three open Criticals — a potential
AES-GCM nonce-reuse break (CR-2), an unauthenticated air-gap trust model that
permits peer-key MITM (CR-3), and an unauthenticated supply chain (CR-4) — plus
the kernel coverage/fail-open-on-detach gaps (HI-1/HI-2) mean the platform cannot
yet be trusted to protect real traffic. The score is **not** a TRL change; it is a
deployment-safety gate.

## Gating findings (must close before an operational pilot)

| # | Finding | Why it gates a pilot |
|---|---|---|
| 1 | **CR-2** fork→nonce reuse | a single fork-after-connect could break confidentiality of a session |
| 2 | **CR-3** air-gap MITM | an adversary on the provisioning media can impersonate a trusted peer |
| 3 | **CR-4** supply-chain RCE | a tampered package yields root on every node |
| 4 | **HI-1** IPv6/UDP bypass | the kernel guarantee does not cover all egress |
| 5 | **HI-2** fail-open on detach | a control-plane crash re-opens egress |

## What is already pilot-grade (do not regress)

- Hybrid PQC handshake, transcript binding, forward secrecy, AES-256-GCM record
  layer with overflow-guarded nonces (read as sound).
- Anti-DoS admission gate (measured: 5 000-source flood → 25 PQC ops).
- Fail-closed posture/state machine with no representable plaintext mode.
- The fixed CR-1 fail-open path (now fails closed, regression-tested).
- Strong test/fuzz/Miri/Loom scaffolding — accelerates remediation verification.

## Conditional-lab-pilot guardrails (if used before the Criticals close)

1. Isolated network; **no traffic of real value**.
2. Provisioning over a trusted local channel only — **do not rely on the air-gap
   integrity claim** (CR-3).
3. Install from a locally-built, locally-verified package — **do not trust a
   distributed tarball** (CR-4).
4. Pin applications to IPv4 TCP for the duration, or treat IPv6/UDP as
   unprotected (HI-1); run the eBPF loader under a supervisor (HI-2 mitigation).
5. Avoid fork-after-connect application patterns, or run with the interceptor
   disabled and rely on the over-socket daemon path until CR-2 is fixed.

## Path to "pilot ready"

Close CR-2, CR-3, CR-4, HI-1, HI-2 (each with its validation gate in
`docs/SECURITY_REMEDIATION_PLAN.md`), re-run this assessment, and target a score
of **≥ 7/10** before an operational pilot. The Low-effort deploy hardening
(HI-6…HI-9) should be done at the same time — high value, low risk.

## TRL impact

This assessment does **not** lower the functional **TRL 5** rating — the
capabilities are still demonstrated. It establishes that **deployment readiness
trails functional readiness**: the security backlog above must close before the
TRL-6 pilot can carry meaningful traffic. In TRL terms, these are the
"relevant-environment hardening" items between a TRL-5 demonstration and a TRL-6
operational pilot.
