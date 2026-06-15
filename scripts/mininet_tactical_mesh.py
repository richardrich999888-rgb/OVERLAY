#!/usr/bin/env python3
"""
SYNTRIASS v2 tactical-mesh cyber range (Mininet).

Provisions an isolated 3-node SDN topology and stress-tests the SYNTRIASS split-
plane engine (commit d5ba4a4) across a real Open vSwitch fabric under tactical
network impairment:

    h1_alpha (10.0.0.1)  ──tc──  s1_gateway (OVS)  ──tc──  h2_bravo (10.0.0.2)
    Tactical Node Alpha          symmetric L2 bridge       daemon backend + ingress

What this script actually does (no placeholders, no mock data):
  * cross-compiles the Rust workspace (`cargo build --release --all-targets`),
    producing libsyntriass_overlay.so + the daemon / syntriass-identity binaries;
  * builds the OVS bridge + two TCLink veth pairs capped to 64 kbps;
  * runs the v2 control daemon (src/bin/daemon.rs) inside h2_bravo's namespace;
  * drives REAL encrypted application traffic across the switch using the v1
    LD_PRELOAD overlay (a plain client on h1 -> plain server on h2, transparently
    PQC/PSK-encrypted by libsyntriass_overlay.so);
  * sweeps three EW jamming profiles via `tc netem loss`: 0% (baseline),
    25% (jamming onset), 45% (severe EW denial);
  * sniffs the s1 bridge port with tcpdump and asserts EXACTLY 0 plaintext-marker
    leaks on the wire for every profile;
  * also runs the in-process Rust harnesses (range_simulation, chaos) for engine
    validation;
  * exports all logs to benchmarks/mininet_local_range/raw_logs.txt;
  * tears down on any signal/exit (kills h2 backends, `net.stop()`, `mn -c`).

Run (root required for Mininet/OVS):
    sudo python3 scripts/mininet_tactical_mesh.py

Peer mode (invoked internally on the Mininet hosts; not for manual use):
    python3 scripts/mininet_tactical_mesh.py --peer server <ip> <port>
    python3 scripts/mininet_tactical_mesh.py --peer client <ip> <port> <message>
"""

import argparse
import os
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path

# --- Topology / crypto constants -------------------------------------------------

SCRIPT = Path(__file__).resolve()
ROOT = SCRIPT.parents[1]
LOG_DIR = ROOT / "benchmarks" / "mininet_local_range"
LOG_PATH = LOG_DIR / "raw_logs.txt"

OVERLAY_SO = ROOT / "target" / "release" / "libsyntriass_overlay.so"
IDENTITY_BIN = ROOT / "target" / "release" / "syntriass-identity"
DAEMON_BIN = ROOT / "target" / "release" / "daemon"

H1_IP = "10.0.0.1"
H2_IP = "10.0.0.2"
APP_PORT = 9443          # LD_PRELOAD overlay app traffic (client h1 -> server h2)
DAEMON_PORT = 9444       # v2 control daemon over-socket listener on h2
LINK_BW_MBIT = 0.064     # 64 kbps tactical radio line
LINK_DELAY = "50ms"      # one-way base latency (satellite-ish)

MARKER = "CONFIDENTIAL_MISSION_DATA_STREAM"

# Deterministic identities (mirror the Rust integration tests).
CLIENT_ED_SEED = "11" * 32
CLIENT_ML_SEED = "22" * 32
SERVER_ED_SEED = "33" * 32
SERVER_ML_SEED = "44" * 32
FALLBACK_PSK = "ab" * 32

# (loss %, label, mode) -- mode selects PQC vs degraded encrypted fallback.
PROFILES = [
    (0, "baseline (no jamming)", "pqc"),
    (25, "jamming onset", "fallback"),
    (45, "severe EW denial", "fallback"),
]


# --- Peer mode (runs on the Mininet hosts, LD_PRELOAD-interposed) -----------------

def run_peer(role, host, port, message):
    """A plaintext-unaware TCP peer. With libsyntriass_overlay.so preloaded the
    bytes on the wire are encrypted; this code never changes."""
    if role == "server":
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((host, port))
        srv.listen(8)
        print(f"[peer-server] listening on {host}:{port}", flush=True)
        srv.settimeout(60)
        conn, _ = srv.accept()
        conn.settimeout(60)
        data = conn.recv(65536)
        text = data.decode("utf-8", errors="replace")
        print(f"[peer-server] received plaintext: {text}", flush=True)
        conn.sendall(b"ACK:" + data)
        conn.close()
        srv.close()
        return 0

    # client
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(120)
    s.connect((host, port))
    s.sendall(message.encode("utf-8"))
    echo = s.recv(65536)
    print(f"[peer-client] echo: {echo.decode('utf-8', errors='replace')}", flush=True)
    s.close()
    return 0


# --- Orchestrator (root + Mininet) ----------------------------------------------

class Tee:
    """Mirror everything to stdout AND the raw_logs.txt dossier file."""

    def __init__(self, path):
        self.f = open(path, "w", buffering=1)

    def log(self, msg=""):
        line = str(msg)
        print(line, flush=True)
        self.f.write(line + "\n")
        self.f.flush()

    def close(self):
        self.f.close()


def sh(cmd, cwd=None, timeout=None):
    """Run a host-side command, returning (rc, combined_output)."""
    p = subprocess.run(
        cmd, cwd=cwd, timeout=timeout, shell=isinstance(cmd, str),
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    )
    return p.returncode, p.stdout


def derive_public_keys(ed_seed, ml_seed):
    rc, out = sh([str(IDENTITY_BIN), ed_seed, ml_seed])
    if rc != 0:
        raise RuntimeError(f"syntriass-identity failed: {out}")
    fields = {}
    for line in out.splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            fields[k.strip()] = v.strip()
    return fields["ed25519_public"], fields["mldsa65_public"]


def peer_env(role, mode, peer_ed_pub, peer_ml_pub, own_ed_seed, own_ml_seed):
    env = {
        "LD_PRELOAD": str(OVERLAY_SO),
        "SYNTRIASS_ED25519_SEED_HEX": own_ed_seed,
        "SYNTRIASS_MLDSA65_SEED_HEX": own_ml_seed,
        "SYNTRIASS_PEER_ED25519_PUB_HEX": peer_ed_pub,
        "SYNTRIASS_PEER_MLDSA65_PUB_HEX": peer_ml_pub,
    }
    if mode == "fallback":
        env["SYNTRIASS_PQC_DEGRADED"] = "1"
        env["SYNTRIASS_FALLBACK_PSK_HEX"] = FALLBACK_PSK
    return env


def build_workspace(tee):
    tee.log("== Cross-compiling the Rust workspace (cargo build --release --all-targets) ==")
    rc, out = sh(["cargo", "build", "--release", "--all-targets"], cwd=str(ROOT), timeout=1800)
    tee.log(out.strip()[-2000:])
    if rc != 0:
        raise RuntimeError("cargo build failed")
    for artifact in (OVERLAY_SO, IDENTITY_BIN, DAEMON_BIN):
        if not artifact.exists():
            raise RuntimeError(f"missing build artifact: {artifact}")
    tee.log(f"OK: built {OVERLAY_SO.name}, {IDENTITY_BIN.name}, {DAEMON_BIN.name}\n")


def set_loss(intf, loss_pct, tee):
    """Apply tc netem loss + the 64 kbps cap + base delay to a TCLink interface."""
    intf.config(
        bw=LINK_BW_MBIT,
        delay=LINK_DELAY,
        loss=loss_pct,
        use_tbf=True,
        max_queue_size=1000,
    )
    tee.log(f"   tc on {intf.name}: bw={LINK_BW_MBIT}Mbit delay={LINK_DELAY} loss={loss_pct}%")


def run_profile(net, h1, h2, s1, identities, loss_pct, label, mode, tee):
    tee.log(f"\n================ PROFILE: {loss_pct}% loss -- {label} ({mode}) ================")

    # 1. Impair both directions of the path symmetrically.
    for intf in (h1.intf(), h2.intf()):
        set_loss(intf, loss_pct, tee)

    (c_ed_pub, c_ml_pub, s_ed_pub, s_ml_pub) = identities
    server_env = peer_env("server", mode, c_ed_pub, c_ml_pub, SERVER_ED_SEED, SERVER_ML_SEED)
    client_env = peer_env("client", mode, s_ed_pub, s_ml_pub, CLIENT_ED_SEED, CLIENT_ML_SEED)

    # 2. Start the tcpdump wire-tap on the s1 port facing h1.
    sniff_intf = s1.intfList()[0].name  # s1-eth0 -> toward h1
    pcap = f"/tmp/syntriass_range_{loss_pct}.pcap"
    s1.cmd(f"rm -f {pcap}")
    tcpdump = s1.popen(["tcpdump", "-i", sniff_intf, "-s", "0", "-U", "-w", pcap, "ip"])
    time.sleep(0.5)

    # 3. Real encrypted app traffic across the switch via the LD_PRELOAD overlay.
    srv = h2.popen(
        ["python3", str(SCRIPT), "--peer", "server", H2_IP, str(APP_PORT)],
        env={**os.environ, **server_env},
    )
    time.sleep(1.0)
    cli = h1.popen(
        ["python3", str(SCRIPT), "--peer", "client", H2_IP, str(APP_PORT), MARKER],
        env={**os.environ, **client_env},
    )
    try:
        cli_out = cli.communicate(timeout=180)[0]
    except subprocess.TimeoutExpired:
        cli.kill()
        cli_out = b"[client TIMED OUT]"
    time.sleep(0.5)
    srv.terminate()
    try:
        srv_out = srv.communicate(timeout=10)[0]
    except subprocess.TimeoutExpired:
        srv.kill()
        srv_out = b""
    cli_out = cli_out.decode(errors="replace") if isinstance(cli_out, bytes) else cli_out
    srv_out = srv_out.decode(errors="replace") if isinstance(srv_out, bytes) else srv_out
    tee.log(f"   [h2 server] {srv_out.strip()}")
    tee.log(f"   [h1 client] {cli_out.strip()}")

    # 4. Stop the sniff and audit the wire for cleartext leaks.
    tcpdump.terminate()
    try:
        tcpdump.communicate(timeout=10)
    except subprocess.TimeoutExpired:
        tcpdump.kill()
    rc, leak = sh(f"grep -a -c '{MARKER}' {pcap} || true")
    leak_count = int(leak.strip() or "0")
    rc, bytecount = sh(f"wc -c < {pcap} || echo 0")
    wire_bytes = bytecount.strip()

    server_decrypted = MARKER in srv_out
    tee.log(f"   wire-capture: {wire_bytes} bytes; plaintext-marker leaks = {leak_count}")
    tee.log(f"   server decrypted the marker: {server_decrypted}")

    ok = (leak_count == 0) and server_decrypted
    tee.log(f"   RESULT [{label}]: {'PASS (0.00% cleartext leak, app delivered)' if ok else 'FAIL'}")
    return ok


def run_engine_harnesses(h1, tee):
    tee.log("\n================ In-process engine harnesses (h1_alpha namespace) ================")
    for args in (
        "--release --test chaos_orchestration fallback_emits_no_cleartext_across_the_wire -- --nocapture",
        "--release --test range_simulation handshake_survives_mild_degradation -- --nocapture",
    ):
        out = h1.cmd(f"cd {ROOT} && cargo test {args} 2>&1 | tail -n 8")
        tee.log(out.strip())


def orchestrate():
    # Mininet imports are deferred so --peer mode needs only stdlib + root-free.
    from mininet.net import Mininet
    from mininet.node import OVSBridge
    from mininet.link import TCLink
    from mininet.log import setLogLevel
    from mininet.clean import cleanup

    if os.geteuid() != 0:
        sys.stderr.write("ERROR: Mininet requires root (sudo). Aborting.\n")
        return 2

    LOG_DIR.mkdir(parents=True, exist_ok=True)
    tee = Tee(LOG_PATH)
    setLogLevel("info")

    net = None
    daemon_proc = None
    results = []

    def teardown(*_):
        tee.log("\n== Teardown: killing h2 backends, stopping net, flushing (mn -c) ==")
        try:
            if daemon_proc is not None:
                daemon_proc.terminate()
        except Exception:
            pass
        try:
            if net is not None:
                net.stop()
        except Exception as e:
            tee.log(f"   net.stop error: {e}")
        try:
            cleanup()  # equivalent to `mn -c`
        except Exception as e:
            tee.log(f"   cleanup error: {e}")
        tee.close()

    signal.signal(signal.SIGINT, lambda *_: (teardown(), sys.exit(130)))
    signal.signal(signal.SIGTERM, lambda *_: (teardown(), sys.exit(143)))

    try:
        build_workspace(tee)

        identities = (
            *derive_public_keys(CLIENT_ED_SEED, CLIENT_ML_SEED),
            *derive_public_keys(SERVER_ED_SEED, SERVER_ML_SEED),
        )

        tee.log("== Building tactical mesh: h1_alpha -- s1_gateway(OVS) -- h2_bravo ==")
        net = Mininet(switch=OVSBridge, link=TCLink, controller=None, autoSetMacs=True)
        h1 = net.addHost("h1_alpha", ip=f"{H1_IP}/24")
        h2 = net.addHost("h2_bravo", ip=f"{H2_IP}/24")
        s1 = net.addSwitch("s1_gateway")
        net.addLink(h1, s1, cls=TCLink, bw=LINK_BW_MBIT, delay=LINK_DELAY)
        net.addLink(h2, s1, cls=TCLink, bw=LINK_BW_MBIT, delay=LINK_DELAY)
        net.build()
        net.start()
        tee.log("   topology up; verifying L2/L3 reachability:")
        tee.log("   " + h1.cmd(f"ping -c1 -W3 {H2_IP}").strip())

        # v2 control daemon as the h2_bravo backend architecture (over-socket mode).
        daemon_env = peer_env("server", "pqc", *identities[:2], SERVER_ED_SEED, SERVER_ML_SEED)
        daemon_env.pop("LD_PRELOAD", None)  # the daemon is the backend, not interposed
        daemon_env["SYNTRIASS_OVERSOCKET_LISTEN"] = f"{H2_IP}:{DAEMON_PORT}"
        daemon_proc = h2.popen([str(DAEMON_BIN)], env={**os.environ, **daemon_env})
        time.sleep(1.0)
        tee.log(f"   v2 daemon backend running on h2_bravo ({H2_IP}:{DAEMON_PORT})")

        for loss, label, mode in PROFILES:
            ok = run_profile(net, h1, h2, s1, identities, loss, label, mode, tee)
            results.append((loss, label, ok))

        run_engine_harnesses(h1, tee)

        tee.log("\n================ SANITY MATRIX SUMMARY ================")
        all_ok = True
        for loss, label, ok in results:
            all_ok = all_ok and ok
            tee.log(f"   {loss:>3}% loss  {label:<24} -> {'0.00% leak / delivered' if ok else 'LEAK OR FAILURE'}")
        tee.log(f"\nOVERALL: {'ALL PROFILES PASSED' if all_ok else 'FAILURES DETECTED'}")
        return 0 if all_ok else 1
    except Exception as e:
        tee.log(f"FATAL: {e}")
        return 1
    finally:
        teardown()


def main():
    ap = argparse.ArgumentParser(description="SYNTRIASS tactical-mesh Mininet range")
    ap.add_argument("--peer", nargs="+", metavar="ARG",
                    help="internal: <role> <host> <port> [message]")
    args = ap.parse_args()

    if args.peer:
        role = args.peer[0]
        host = args.peer[1]
        port = int(args.peer[2])
        message = args.peer[3] if len(args.peer) > 3 else MARKER
        return run_peer(role, host, port, message)

    return orchestrate()


if __name__ == "__main__":
    raise SystemExit(main())
