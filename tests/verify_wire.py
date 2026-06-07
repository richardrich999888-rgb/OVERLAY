#!/usr/bin/env python3
"""End-to-end verification for the Syntriass overlay.

Topology (the relay is the neutral 'wire' observer; it is NEVER preloaded):

    client  --->  relay (records bytes)  --->  server

We run two scenarios:

  1. BASELINE (no overlay): the relay must observe the plaintext marker, proving
     the legacy app is exposed on the wire.

  2. OVERLAY (LD_PRELOAD on client AND server): the relay must NOT observe the
     marker, yet the server must still print the correct plaintext -- proving the
     tunnel is transparent to the app and opaque on the wire.

This uses a userspace relay rather than raw-socket / tcpdump capture so the test
runs without root or CAP_NET_RAW. It genuinely observes the bytes in transit.

Exit code 0 = all assertions passed.
"""
import os
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
APP = str(HERE / "vulnerable_app.py")
MARKER = b"CONFIDENTIAL_MISSION_DATA_STREAM"


def find_lib() -> str:
    for name in ("libsyntriass_overlay.so",):
        p = ROOT / "target" / "release" / name
        if p.exists():
            return str(p)
    raise FileNotFoundError(
        "built library not found; run `cargo build --release` first"
    )


def free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class Relay:
    """Single-connection TCP relay that records all bytes in both directions."""

    def __init__(self, listen_port: int, target_port: int):
        self.listen_port = listen_port
        self.target_port = target_port
        self.captured = bytearray()
        self._lock = threading.Lock()
        self._srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._srv.bind(("127.0.0.1", listen_port))
        self._srv.listen(1)
        self._thread = threading.Thread(target=self._serve, daemon=True)

    def start(self):
        self._thread.start()

    def _pump(self, src, dst, record):
        try:
            while True:
                chunk = src.recv(4096)
                if not chunk:
                    break
                if record:
                    with self._lock:
                        self.captured.extend(chunk)
                dst.sendall(chunk)
        except OSError:
            pass
        finally:
            try:
                dst.shutdown(socket.SHUT_WR)
            except OSError:
                pass

    def _serve(self):
        client, _ = self._srv.accept()
        upstream = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        upstream.connect(("127.0.0.1", self.target_port))
        # Record only client->server direction; that's where the secret travels.
        t1 = threading.Thread(target=self._pump, args=(client, upstream, True), daemon=True)
        t2 = threading.Thread(target=self._pump, args=(upstream, client, False), daemon=True)
        t1.start(); t2.start()
        t1.join(); t2.join()
        client.close(); upstream.close()

    def wire_bytes(self) -> bytes:
        with self._lock:
            return bytes(self.captured)


def run_scenario(preload: str | None) -> tuple[bytes, str]:
    """Returns (bytes_seen_on_wire, server_stdout)."""
    server_port = free_port()
    relay_port = free_port()

    relay = Relay(relay_port, server_port)
    relay.start()

    env = dict(os.environ)
    if preload:
        env["LD_PRELOAD"] = preload

    server = subprocess.Popen(
        [sys.executable, APP, "server", str(server_port)],
        env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    )
    time.sleep(0.5)  # let the server bind/listen

    client = subprocess.Popen(
        [sys.executable, APP, "client", str(relay_port), MARKER.decode()],
        env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    )

    try:
        client.wait(timeout=10)
        server.wait(timeout=10)
    except subprocess.TimeoutExpired:
        client.kill(); server.kill()
        raise

    server_out = server.stdout.read() if server.stdout else ""
    time.sleep(0.2)
    return relay.wire_bytes(), server_out


def main() -> int:
    try:
        lib = find_lib()
    except FileNotFoundError as e:
        print(f"FAIL: {e}")
        return 1

    print("== Scenario 1: BASELINE (no overlay) ==")
    wire, out = run_scenario(preload=None)
    print(out.strip())
    if MARKER not in wire:
        print("FAIL: baseline did not expose plaintext on the wire (test setup broken)")
        return 1
    print(f"OK: plaintext marker visible on wire ({len(wire)} bytes captured)\n")

    print("== Scenario 2: OVERLAY (LD_PRELOAD both ends) ==")
    wire, out = run_scenario(preload=lib)
    print(out.strip())
    if MARKER in wire:
        print("FAIL: marker LEAKED on the wire under overlay")
        return 1
    if MARKER.decode() not in out:
        print("FAIL: server did not receive correct plaintext under overlay")
        return 1
    print(f"OK: wire is opaque ({len(wire)} bytes, no marker) AND server saw plaintext\n")

    print("ALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
