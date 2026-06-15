# Mininet tactical-mesh range

Driver: [`scripts/mininet_tactical_mesh.py`](../../scripts/mininet_tactical_mesh.py).

Provisions an isolated `h1_alpha — s1_gateway(OVS) — h2_bravo` topology, caps the
links to **64 kbps**, sweeps EW jamming via `tc netem loss` at **0% / 25% / 45%**,
runs the v2 daemon on `h2_bravo`, drives real encrypted application traffic across
the switch with the v1 `LD_PRELOAD` overlay, and sniffs `s1` with `tcpdump` to
assert **0.00% plaintext-marker leak** on the wire for every profile.

## Run (requires a host with Mininet + Open vSwitch + iproute2 + tcpdump)

```bash
sudo python3 scripts/mininet_tactical_mesh.py
```

All terminal output, performance counters and the per-profile leak audit are
exported to `raw_logs.txt` in this directory. Teardown (h2 backends killed,
`net.stop()`, `mn -c`) runs on any signal or exit.

## Environment note (this sandbox)

This CI/dev sandbox has **no** Mininet stack (`mn`, `ovs-vsctl`, `ip`, `tc`,
`tcpdump` are absent, and the kernel lacks the `sch_netem`/`tbf` modules), so the
full topology cannot be launched here — it runs on a provisioned Mininet VM. What
*was* validated in-sandbox:

- `python3 -m py_compile scripts/mininet_tactical_mesh.py` — script is valid;
- `cargo build --release --all-targets` — the build step the script runs;
- the script's **`--peer` overlay client/server logic over real loopback sockets
  with the actual `libsyntriass_overlay.so` preloaded**: the client connects, the
  overlay performs the full X25519 + ML-KEM + ML-DSA handshake transparently,
  encrypts the stream, and the server decrypts the mission marker and echoes the
  ACK. On the Mininet host those same processes run on `h1`/`h2` across the OVS
  fabric, so `tcpdump` on `s1` observes only ciphertext.

The structural cleartext guarantee (no `AvailabilityPosture::Plaintext`, overlay
only ever seals) and the userspace-proxy degradation P50/P99 are covered by
`tests/chaos_orchestration.rs` and `tests/range_simulation.rs`.
