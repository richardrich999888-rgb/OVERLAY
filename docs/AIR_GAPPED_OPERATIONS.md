# Air-Gapped Operations — Migration Platform Phase 5

Tags: **[tested]** real run on this host · **[implemented]** code/script exists ·
**[design]** needs external infra.

**Objective:** support defence deployments with **no internet dependency** —
offline identity provisioning, offline updates, and offline policy distribution,
all carried across an air gap on removable media with integrity verification.

All tooling is in `deploy/airgap.sh` (+ `deploy/package.sh` from Phase 4). Every
step below was executed on this host with **zero network access**; every
transferred artifact carries a SHA-256 self-checksum verified on import
(fail-closed: a checksum mismatch refuses the import).

---

## 1. Offline identity provisioning — **[tested]**

Each node generates its own secrets locally from `/dev/urandom` and derives its
public keys with the local `syntriass-identity` binary — **no key server, no
network**:

```sh
sudo deploy/install.sh --provision-self          # local seeds + derive own public keys
deploy/airgap.sh export-identity /media/usb/A.id # write THIS node's PUBLIC identity
```

The export is **public only** (Ed25519 + ML-DSA public keys + a fingerprint);
the secret seeds never leave the host. Carry `A.id` to the peer on removable
media.

### Peer exchange (sneakernet) — **[tested]**

```sh
deploy/airgap.sh import-peer /media/usb/B.id     # verify checksum, set peer_* in identity.toml
sudo syntriass-overlay-validate-config           # -> configuration VALID
```

**Validated on this host:** two nodes A and B each exported their public
identity, cross-imported the other's over "removable media", and **both
validated VALID with zero network**. A corrupted export is **refused**
(`checksum mismatch … refusing import (fail closed)`).

## 2. Offline updates — **[tested]**

`deploy/package.sh` produces a self-contained tarball (prebuilt binaries +
scripts + unit + `SHA256SUMS`); it installs with no source tree and no network:

```sh
# on a connected build host:
deploy/package.sh --out ./dist          # -> syntriass-overlay-<ver>-<arch>.tar.gz (+ .sha256)
# carry the tarball to the air-gapped host, then:
sha256sum -c syntriass-overlay-<ver>-<arch>.tar.gz.sha256   # integrity
tar xzf syntriass-overlay-<ver>-<arch>.tar.gz
cd syntriass-overlay-<ver>-<arch> && sudo ./install.sh      # offline install
# upgrades use the same artifact:
sudo deploy/upgrade.sh --from ./bin     # backup + install + revalidate + auto-restore on failure
```

**Validated on this host:** package built (2.8 MB), `sha256sum -c SHA256SUMS`
verified **every file OK**; upgrade+rollback cycle left the binary byte-identical
(Phase 4). No network is contacted at any point.

## 3. Offline policy distribution — **[tested]**

A policy bundle (cipher suite) is built, carried, and applied offline with
checksum verification:

```sh
deploy/airgap.sh make-policy-bundle nist1024 /media/usb/pol.tar.gz   # build (checksummed)
deploy/airgap.sh apply-policy-bundle /media/usb/pol.tar.gz           # verify + install policy.toml
```

**Validated on this host:** a `nist1024` bundle was built and applied
(`policy.toml` suite=nist1024); a **tampered bundle** (policy.toml changed,
`SHA256SUMS` stale) was **refused** (`checksum FAILED — refusing to apply (fail
closed)`), as was a corrupted archive.

## 4. Success criteria — status

| Criterion (mission) | Status |
|---|---|
| Offline identity provisioning | ✅ [tested] local seeds + `export-identity`/`import-peer`, checksum-verified |
| Offline updates | ✅ [tested] `package.sh` tarball + `SHA256SUMS` + `upgrade.sh`, no network |
| Offline policy distribution | ✅ [tested] `make-`/`apply-policy-bundle`, tamper-rejected |
| **No internet dependency required** | ✅ [tested] every step ran with zero network; integrity by SHA-256 |

## 5. Residual / boundary

- **[design]** Artifact **signing**: integrity today is SHA-256 self-checksums
  (detect corruption/accidental tamper). A detached signature (GPG / cosign / an
  ML-DSA signature using the identity tool) over `SHA256SUMS` and over identity
  exports would add **authenticity** against an active adversary on the
  sneakernet path — the highest-value next hardening step.
- **[design]** Offline **CRL distribution**: revocations (Phase 1
  `PeerRegistry::revoke`) should ride the same bundle mechanism (a revoked-hash
  list carried on media and applied offline). The revocation mechanism is
  implemented + tested; the offline-CRL bundle is the remaining wiring.
- Provisioning is point-to-point here; fleet-scale offline distribution is
  `docs/FLEET_MANAGEMENT.md`.

## 6. Readiness impact

SYNTRIASS can be provisioned, updated, and re-policied entirely across an air gap
with integrity verification and fail-closed rejection of tampered artifacts —
the baseline a classified/disconnected defence deployment requires. See
`docs/DEFENCE_READINESS_REVIEW.md` row **MIG-5**.
