#!/usr/bin/env python3
"""End-to-end proof of the encrypted PSK fallback path (degraded posture).

Both endpoints run the overlay with `SYNTRIASS_PQC_DEGRADED=1` (the asymmetric
control path is "down") and a shared `SYNTRIASS_FALLBACK_PSK_HEX`. The overlay
must then negotiate the authenticated AES-256-GCM PSK fallback instead of the
hybrid PQC handshake — and crucially must NEVER put the plaintext marker on the
wire.

A neutral recording relay (never preloaded) observes the client->server bytes.

Asserts:
  1. the first wire frame is a FallbackHello (header suite-id byte == 0xFE),
     proving the degraded fallback negotiation actually ran;
  2. the plaintext marker never appears on the wire (encrypted);
  3. the server application still receives the correct plaintext (transparent).

Exit 0 = all assertions passed.
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
FALLBACK_WIRE_ID = 0xFE
PSK_HEX = "ab" * 32  # 32-byte pre-shared key, shared by both endpoints


def find_lib() -> str:
    p = ROOT / "target" / "release" / "libsyntriass_overlay.so"
    if not p.exists():
        raise FileNotFoundError("run `cargo build --release` first")
    return str(p)


def free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class Relay:
    """Single-connection TCP relay recording client->server bytes."""

    def __init__(self, listen_port: int, target_port: int):
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
        t1 = threading.Thread(target=self._pump, args=(client, upstream, True), daemon=True)
        t2 = threading.Thread(target=self._pump, args=(upstream, client, False), daemon=True)
        t1.start(); t2.start(); t1.join(); t2.join()
        client.close(); upstream.close()

    def wire(self) -> bytes:
        with self._lock:
            return bytes(self.captured)


def run() -> int:
    try:
        lib = find_lib()
    except FileNotFoundError as e:
        print(f"FAIL: {e}")
        return 1

    server_port = free_port()
    relay_port = free_port()
    relay = Relay(relay_port, server_port)
    relay.start()

    env = dict(os.environ)
    env["LD_PRELOAD"] = lib
    env["SYNTRIASS_PQC_DEGRADED"] = "1"            # asymmetric control "down"
    env["SYNTRIASS_FALLBACK_PSK_HEX"] = PSK_HEX    # shared quantum-safe PSK

    server = subprocess.Popen(
        [sys.executable, APP, "server", str(server_port)],
        env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    )
    time.sleep(0.5)
    client = subprocess.Popen(
        [sys.executable, APP, "client", str(relay_port), MARKER.decode()],
        env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    )
    try:
        client.wait(timeout=10)
        server.wait(timeout=10)
    except subprocess.TimeoutExpired:
        client.kill(); server.kill()
        print("FAIL: timed out")
        return 1
    server_out = server.stdout.read() if server.stdout else ""
    time.sleep(0.2)
    wire = relay.wire()

    print("== Encrypted PSK fallback (degraded posture) ==")
    print(server_out.strip())

    if len(wire) < 6:
        print(f"FAIL: too few bytes on the wire ({len(wire)})")
        return 1
    if wire[4] != FALLBACK_WIRE_ID:
        print(f"FAIL: first frame suite-id is 0x{wire[4]:02x}, expected 0x{FALLBACK_WIRE_ID:02x} "
              "(fallback negotiation did not run)")
        return 1
    print(f"OK: first wire frame is a FallbackHello (suite-id 0x{wire[4]:02x})")

    if MARKER in wire:
        print("FAIL: plaintext marker LEAKED on the wire under fallback")
        return 1
    print(f"OK: wire is opaque ({len(wire)} bytes, no plaintext marker)")

    if MARKER.decode() not in server_out:
        print("FAIL: server did not receive the correct plaintext")
        return 1
    print("OK: server received correct plaintext (transparent to the app)")

    print("\nALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(run())
