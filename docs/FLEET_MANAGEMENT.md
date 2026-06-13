# Fleet Management Foundation — Migration Platform Phase 6

Tags: **[tested]** real run on this host · **[implemented]** code exists ·
**[design]** needs external infra.

**Objective:** an enterprise-scale (**100+ node**) management foundation — node
inventory, policy distribution, health reporting, identity status, and posture
status — that works **offline-first** (air-gap compatible). Tool: `deploy/fleet.sh`.

**Tested at 120 nodes on this host** (3 imported from real air-gap identity
exports, 117 synthetic at scale). Everything is plain files that travel on
removable media; nothing contacts the network.

---

## 1. Architecture

```
  per-node (offline)                 fleet operator (offline)
  ┌──────────────┐  export-identity   ┌────────────────────────┐
  │ node identity│ ─────────────────▶ │ inventory.tsv          │
  │ (seeds local)│                    │  id│fp│profile│posture │
  └──────┬───────┘                    │    │health│last_seen   │
         │ health record  ──────────▶ │ ingest-health          │
         ▼                            │ distribute ─▶ policy-*  │
  apply policy bundle ◀────────────── │  bundles + assignments  │
                                      │ status ─▶ aggregate     │
                                      └────────────────────────┘
```

The **inventory** is a TSV — `node_id │ fingerprint │ profile │ posture │ health
│ last_seen` — chosen because it scales to thousands of rows, diffs cleanly in
git/CM, and carries on a USB stick. Identity is referenced by the 16-hex
**fingerprint** of the node's public keys (from `airgap.sh export-identity`);
the fleet store never holds a secret.

`profile ∈ {strategic-command, tactical-comms, legacy-migration}` (the three
DefenceProfiles); `posture ∈ {FullPqc, EncryptedFallback, FailClosed}` — **there
is no plaintext posture**, by construction, fleet-wide.

## 2. Capabilities — **[tested]**

| Capability | Command | Result at 120 nodes |
|---|---|---|
| **Node inventory** | `init` / `add` / `import-node <export>` | 120 nodes registered; 3 imported from real air-gap identity exports (fingerprint parsed from the signed export) |
| **Policy distribution** | `distribute <inv> <outdir>` | per-profile offline policy bundles (`policy-strategic-command.tar.gz`, …) + `assignments.tsv` mapping all 120 nodes → profile; bundles are the Phase-5 checksummed `airgap` bundles, carried to nodes offline |
| **Health reporting** | `ingest-health <inv> <file>` | node-reported `posture`+`health`+`epoch` records ingested; bad postures rejected |
| **Identity status** | `status` (fingerprint column) | every node carries its identity fingerprint |
| **Posture status** | `status` (by posture) | FullPqc 118 / EncryptedFallback 1 / FailClosed 1 |
| **Health/liveness** | `status [--stale-secs N]` | by-health counts + never-reported + stale; **ALERT on FailClosed** nodes |

### Example status (120-node run)

```
==== SYNTRIASS fleet status (120 nodes) ====
-- by profile --   tactical-comms 90 · strategic-command 13 · legacy-migration 17
-- by posture --   FullPqc 118 · EncryptedFallback 1 · FailClosed 1
-- by health  --   ok 118 · degraded 1 · down 1
-- liveness --     never-reported 0 · stale 0
  ALERT: 1 node(s) FailClosed
```

The status roll-up gives an operator the fleet's cryptographic posture, profile
mix, and liveness at a glance, and **alerts** when any node has gone FailClosed
(lost a safe channel) — the signal a defence operator acts on.

## 3. Scale — **[tested]** 120 / **[design]** beyond

- **120 nodes** exercised here (inventory build, distribution, health ingest,
  status) in seconds; the TSV + awk roll-up is O(N) and comfortably handles
  thousands of rows.
- The model is **pull/offline**: nodes apply their assigned bundle and emit a
  health record; the operator ingests records carried back on media. This is the
  air-gap-safe foundation; an **online** control-plane transport (push
  distribution + live health stream, mTLS over the overlay itself) is **[design]**
  — the same "networked fleet distribution transport" noted in
  `docs/MULTINODE_VALIDATION.md` §5.

## 4. Success criteria — status

| Criterion (mission) | Status |
|---|---|
| Node inventory | ✅ [tested] init/add/import-node, 120 nodes |
| Policy distribution | ✅ [tested] per-profile offline bundles + assignments for all nodes |
| Health reporting | ✅ [tested] ingest-health + by-health roll-up |
| Identity status | ✅ [tested] fingerprint per node |
| Posture status | ✅ [tested] by-posture roll-up + FailClosed alert |
| 100+ node architecture documented and tested | ✅ [tested] **120 nodes**; online transport [design] |

## 5. Residual / boundary

- **[design]** Online control plane: push distribution + a live health stream
  carried over the overlay (authenticated, fail-closed), and CRL/revocation
  fan-out (Phase-1 `revoke()` + Phase-5 offline-CRL bundle) wired into
  `distribute`.
- **[design]** Inventory authenticity: the inventory + assignments should be
  signed (same signing gap as Phase 5) so a tampered assignment is detectable.
- Integrates with the validated runtime: the multi-node workstream proved 50
  real PQC sessions and fleet-wide fail-closed (`docs/MULTINODE_VALIDATION.md`);
  this phase adds the management plane over that runtime.

## 6. Readiness impact

SYNTRIASS has an offline-first fleet-management foundation that inventories,
policies, and reports on 100+ nodes with identity/posture/health visibility and
FailClosed alerting — the operational substrate for an enterprise or theatre
deployment. See `docs/DEFENCE_READINESS_REVIEW.md` row **MIG-6**.
