# Package Signing Architecture

**Internal Security Hardening and Pre-Audit Remediation.**

## Components
- **Manifest**: deterministic `path\t<sha256-hex>\n` lines over every file in the
  package (sorted paths for reproducibility).
- **SignedBundle(Package)**: hybrid Ed25519+ML-DSA signature over the canonical
  message `{domain, "package", signer-id, version, manifest-bytes}` (`src/airgap.rs`).
- **TrustStore**: pinned signer anchors + revocation + per-(kind,signer) version
  floor.
- **Installer gate**: verify manifest signature → recompute + compare every file
  hash → only then extract/execute.

## Build → distribute → install flow
```
build host (offline, signer key sealed)        target host (offline-capable)
  package.sh                                      install.sh
   ├─ assemble files                               ├─ load pinned anchor (bring-up)
   ├─ build manifest (path -> sha256)              ├─ from_bytes(manifest.sig)
   ├─ SignedBundle::sign(Package, key, ver)        ├─ TrustStore.verify  (fail closed)
   └─ emit pkg.tar + manifest.sig                  ├─ per-file sha256 == manifest?
                                                    └─ only then install -m 0755 / run
```

## Properties
- **No unsigned/modified/forged/replayed/rollback package executes** (tested,
  `tests/cr4_supply_chain_tests.rs`).
- **Quantum-safe**: ML-DSA component means a future quantum adversary cannot forge
  a package signature; Ed25519 adds classical defence-in-depth (both required).
- **Reproducible-build friendly**: the manifest is deterministic; pair with a
  pinned toolchain + SBOM (`cargo audit`) for full supply-chain assurance ([design]).

## Implemented vs design
- `[implemented] [tested]`: manifest concept, signing, verification, the installer
  gate logic, on-disk format, all reject paths.
- `[design]`: `package.sh`/`install.sh` rewiring; offline key custody + anchor
  bring-up procedure; signed revocation lists; reproducible-build + SBOM pipeline.
