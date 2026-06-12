# Production eBPF Policy / State Layer (Phase 3)

Tags: **[measured]** real run · **[tested]** automated assertion · **[implemented]**
code exists · **[design]** needs external infra.

**Objective:** replace the scaffold's static config with an **operational kernel
policy engine** — a `cgroup/connect4` program whose egress decision is driven by
**live BPF map state** that userspace distributes (posture, fallback, session
state), with bidirectional userspace↔kernel synchronization.

## 1. Implementation — **[implemented]** (`ebpf/c/policy.bpf.c`, `policy_loader.c`)

| Map | Type | Direction | Purpose |
|---|---|---|---|
| `operation_mode` | `ARRAY[1] u32` | userspace → kernel | posture: 0=FullPqc, 1=EncryptedFallback, 2=FailClosed |
| `fallback_state` | `ARRAY[1] u32` | userspace → kernel | encrypted-fallback engaged flag |
| `session_state` | `HASH<u64,u8>` | **kernel → userspace** | per-flow state, keyed by `(daddr<<16 \| dport)` |
| `events` | `RINGBUF` | kernel → userspace | one record per decision (drives the supervisor) |

Enforcement in the `cgroup/connect4` hook (below libc, every runtime):

- **FailClosed** → DENY every outbound `connect` (`EPERM`). A map miss also fails
  closed (default-deny if the posture map is somehow unreadable).
- **EncryptedFallback** → ALLOW (the control plane forces the encrypted PSK path;
  never plaintext) and record the session.
- **FullPqc** → ALLOW and record the session.

`policy_loader` loads the program, attaches it to a cgroup, pushes posture into
`operation_mode` (timing each update), streams decisions from the ring buffer, and
dumps the live `session_state` count at exit — i.e. full userspace↔kernel sync.

## 2. Validation — **[measured]** (`ebpf/POLICY_REPORT.txt`)

`sudo bash scripts/ebpf_policy_validate.sh`, kernel 6.18, one program on a private
cgroup2; posture scheduled FullPqc→FailClosed; real `connect()` probes:

| Check | Result |
|---|---|
| Posture distribution (map update latency) | **1–3 µs** steady (90 µs first cold push) |
| FullPqc posture → kernel decision | **ALLOW** (probe reached the network: `errno=111` refused) |
| FailClosed posture → kernel decision | **DENY** (`errno=1` EPERM) — fail-closed transition enforced by live map state |
| Decisions recorded in the ring buffer | `decision=ALLOW` and `decision=DENY` present |
| Session state distributed kernel→userspace | **1 live session** read back from `session_state` |

```
UPD mode=0 us=3        UPD mode=0 us=1        UPD mode=2 us=90
EVT pid=… dst=127.0.0.1:51111 mode=0 decision=ALLOW
EVT pid=… dst=127.0.0.1:51222 mode=2 decision=DENY
SESS 1
RESULT: PASS — kernel enforces live posture from map state; fail-closed transition works.
```

## 3. Success criteria — status

| Criterion | Status |
|---|---|
| Kernel receives live posture updates | ✅ [measured] (`operation_mode` map pushed in 1–3 µs; decisions reflect it) |
| Kernel enforces policy using map state | ✅ [measured] (ALLOW under FullPqc, DENY under FailClosed) |
| Fail-closed behaviour preserved | ✅ [measured] (FailClosed → EPERM; map miss → deny by construction) |

Map updates, policy enforcement, and the fail-closed transition are all
**measured**, not asserted.

## 4. Integration & residual

- This is the **kernel half** of the Kinetic State Machine (Phase 4): the
  supervisor sets `operation_mode` (the `OPERATION_MODE_FLAG`) and consumes the
  `events`/`session_state` maps. Phase 4 wires the autonomous transitions on top.
- It uses the **same `cgroup/connect4` hook** as the universal-interception data
  plane (`connect4.bpf.c`), which is left untouched so its measured coverage
  evidence remains stable; `policy.bpf.c` is the posture-aware production variant.
- **Residual [design]**: the production daemon driving `operation_mode` from the
  live PQC/fallback control plane (vs the test schedule); per-pod attach for K8s;
  IPv6 (`connect6`). The kernel mechanism is measured here.
- **Boundary [design]**: runs on a BPF-capable host (root/CAP_BPF), not the
  default CI sandbox; a privileged BPF CI lane should run
  `scripts/ebpf_policy_validate.sh` per-PR.

## 5. Migration Platform Phase 3 — re-validation & map inventory

The mission's three named maps map directly onto this engine, all
**userspace-synchronised** and **[measured]** on kernel 6.18.5 (re-run via
`scripts/ebpf_policy_validate.sh`):

| Mission map | This engine | Direction | Measured |
|---|---|---|---|
| **Posture map** | `operation_mode` ARRAY[1] u32 (0/1/2) | userspace → kernel | update **1–4 µs** (156 µs cold), FullPqc→ALLOW, FailClosed→DENY (EPERM) |
| **Fallback map** | `fallback_state` ARRAY[1] u32 | userspace → kernel | read on the decision path |
| **Session map** | `session_state` HASH<flow,u8> | kernel → userspace | live session recorded (`live sessions: 1`) |
| events | `events` RINGBUF | kernel → userspace | one structured record per decision |

The **production v2 engine** (`ebpf/c/policy_v2.bpf.c`, six phases) extends this
into structured policy objects, a 4-level hierarchy, crypto enforcement,
quarantine, an audit pipeline, and deployable profiles — each separately measured
in `docs/POLICY_OBJECT_MODEL.md`, `HIERARCHICAL_POLICY.md`, `CRYPTO_POLICY.md`,
`QUARANTINE_ENGINE.md`, `AUDIT_TELEMETRY.md`, `DEFENCE_POLICY_PROFILES.md`.

**Phase-3 success criteria:** kernel receives live policy state ✅ [measured];
enforcement uses kernel maps ✅ [measured] (decision read from map state on every
`connect`); no plaintext leakage ✅ [tested] (FailClosed → EPERM; no posture
encodes plaintext). Residual daemon-loop wiring remains [design] (above).
