# SYNTRIASS Overlay — Deployment Guide (Migration Platform Phase 4)

Tags: **[tested]** real run on this host · **[implemented]** code/script exists ·
**[design]** needs systemd PID 1 (not present in this container).

A fresh Linux host can **install → configure → start → validate** SYNTRIASS
Overlay **without modifying source code**, from either the source tree or an
offline package. Every step below was executed on this host; the systemd
enable/start path is `[design]` here only because this container has no systemd
PID 1 (the unit file is installed and `validate-config` runs as its
`ExecStartPre`).

All deployment assets live in `deploy/`.

---

## 1. Quick start (from the source tree)

```sh
cargo build --release --locked                     # build the three binaries
sudo deploy/install.sh --provision-self            # install + generate THIS node's identity
# share the printed this_node_*_public keys with your peer (out-of-band),
# then set peer_ed25519_public / peer_mldsa65_public in /etc/syntriass/identity.toml
sudo syntriass-overlay-validate-config             # must print "configuration VALID"
sudo systemctl enable --now syntriass-overlay.service   # [design here] start under systemd
```

## 2. What gets installed — **[tested]**

| Path | Purpose |
|---|---|
| `/usr/local/bin/syntriass-daemon` | the overlay daemon (over-socket responder + fd-passing + anti-DoS gate) |
| `/usr/local/bin/syntriass-identity` | derive public keys from seeds (provisioning) |
| `/usr/local/bin/syntriass-webhook` | metrics / admission webhook |
| `/usr/local/bin/syntriass-overlay-validate-config` | the fail-closed config validator |
| `/etc/syntriass/policy.toml` | cipher suite (`nist768` \| `nist1024`) |
| `/etc/syntriass/identity.toml` | this node's seeds + the trusted peer's public keys (mode 0600) |
| `/etc/systemd/system/syntriass-overlay.service` | hardened unit (DynamicUser-style sandbox, `ProtectSystem=strict`, empty `CapabilityBoundingSet`, `MemoryDenyWriteExecute`) |

Cargo bin `daemon` is installed as `syntriass-daemon` (and `webhook` as
`syntriass-webhook`) so the names are unambiguous on a shared host.

## 3. Configuration contract — **[tested]**

The daemon reads identity from **environment variables OR** `/etc/syntriass/
identity.toml` (env wins — the same precedence the validator enforces):

| Field (toml key / env var) | Size | Meaning |
|---|---|---|
| `ed25519_seed` / `SYNTRIASS_ED25519_SEED_HEX` | 64 hex (32 B) | this node's secret |
| `mldsa65_seed` / `SYNTRIASS_MLDSA65_SEED_HEX` | 64 hex (32 B) | this node's secret |
| `peer_ed25519_public` / `SYNTRIASS_PEER_ED25519_PUB_HEX` | 64 hex (32 B) | trusted peer |
| `peer_mldsa65_public` / `SYNTRIASS_PEER_MLDSA65_PUB_HEX` | 3904 hex (1952 B) | trusted peer |
| `suite` (policy.toml) / `SYNTRIASS_SUITE` | — | `nist768` \| `nist1024` |
| `SYNTRIASS_OVERSOCKET_LISTEN` | — | `host:port` the responder binds (unit default `0.0.0.0:8443`) |

### Validation (fail-closed) — **[tested]**

`syntriass-overlay-validate-config` runs as the unit's `ExecStartPre`, so the
service **will not start** with a missing/weak/malformed identity. Proven on this
host:

- placeholder template ⇒ **exit 1** ("configuration INVALID", each empty field
  reported);
- all-zero seeds ⇒ rejected ("placeholder identity");
- a complete, correctly-sized identity ⇒ **exit 0** ("configuration VALID").

## 4. Start & verify — **[tested]** (bind) / **[design]** (systemd here)

The daemon starts from the file config with no source changes and binds its
listener (verified on this host):

```
$ sudo SYNTRIASS_OVERSOCKET_LISTEN=127.0.0.1:8443 syntriass-daemon
syntriass daemon over-socket responder (anti-DoS gate active) listening on 127.0.0.1:8443
```

Under systemd (`[design]` in this container; standard on a real host):
`systemctl status syntriass-overlay`, `journalctl -u syntriass-overlay`.

## 5. Offline package — **[tested]**

`deploy/package.sh` builds a self-contained, **air-gap-installable** tarball
(see `docs/AIR_GAPPED_OPERATIONS.md`):

```sh
deploy/package.sh --out ./dist
#  -> dist/syntriass-overlay-<version>-<arch>.tar.gz  (2.8 MB)
#  -> dist/...tar.gz.sha256
```

The tarball contains the prebuilt binaries, all `deploy/` scripts, the unit,
config templates, docs, a top-level `install.sh` shim, and a `SHA256SUMS`
manifest. Verified on this host: **`sha256sum -c SHA256SUMS` → all files OK**.
On the target: `tar xzf …; sudo ./install.sh --provision-self` — no network, no
source tree.

## 6. Upgrade & rollback — **[tested]**

```sh
sudo deploy/upgrade.sh --from /path/to/new/binaries   # backs up, installs, re-validates, restarts
sudo deploy/rollback.sh                               # restores the most recent backup, re-validates
```

- **Upgrade** backs up the current binaries to `/var/lib/syntriass/backups/<UTC>`,
  installs the new ones, and **re-validates**; if validation fails it
  **auto-restores** the previous binaries and aborts (fail-closed upgrade).
- **Rollback** restores `backups/latest` (or a named timestamp) and re-validates.
- Verified on this host: an upgrade+rollback cycle left the daemon binary
  byte-identical and the config valid throughout. Config/identity are never
  touched by either operation.

## 7. Uninstall

```sh
sudo deploy/uninstall.sh           # remove binaries + unit, KEEP /etc/syntriass + state
sudo deploy/uninstall.sh --purge   # also remove config, identity, state, and the service user
```

## 8. Success criteria — status

| Criterion (mission) | Status |
|---|---|
| Fresh host can **install** | ✅ [tested] `install.sh` (staged + real) |
| can **configure** | ✅ [tested] templates + `--provision-self` + identity contract |
| can **start** | ✅ [tested] daemon binds from file config; systemd unit installed ([design] start here) |
| can **validate** | ✅ [tested] `validate-config` fail-closed (invalid⇒exit 1, valid⇒exit 0) |
| **without source modification** | ✅ [tested] all of the above used only built binaries + scripts |

## 9. Residual / boundary

- **[design]** systemd `enable --now` / `restart` is not exercised in this
  container (no PID 1); the unit + `ExecStartPre` validator are installed and the
  scripts call `systemctl` only when `/run/systemd/system` exists.
- **[design]** package signing (the tarball ships a SHA256 manifest; a detached
  GPG/cosign signature over `SHA256SUMS` is the next hardening step).
- Provisioning here is point-to-point (own seeds + one peer's public keys); the
  multi-peer / fleet rollout is `docs/FLEET_MANAGEMENT.md`.
