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
from typing import Optional

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
APP = str(HERE / "vulnerable_app.py")
MARKER = b"CONFIDENTIAL_MISSION_DATA_STREAM"
HDR_LEN = 4  # frame header: [body_len: 4 BE] precedes [suite_id][tag][payload]
CLIENT_ED_SEED = "11" * 32
CLIENT_ML_SEED = "22" * 32
SERVER_ED_SEED = "33" * 32
SERVER_ML_SEED = "44" * 32


def find_lib() -> str:
    for name in ("libsyntriass_overlay.so",):
        p = ROOT / "target" / "release" / name
        if p.exists():
            return str(p)
    raise FileNotFoundError(
        "built library not found; run `cargo build --release` first"
    )


def find_identity_tool() -> str:
    p = ROOT / "target" / "release" / "syntriass-identity"
    if p.exists():
        return str(p)
    raise FileNotFoundError(
        "identity helper not found; run `cargo build --release` first"
    )


def derive_identity(tool: str, ed_seed: str, ml_seed: str) -> dict[str, str]:
    out = subprocess.check_output([tool, ed_seed, ml_seed], text=True)
    result: dict[str, str] = {}
    for line in out.splitlines():
        key, value = line.split("=", 1)
        result[key] = value
    return result


def overlay_suite() -> str:
    """Suite token the harness propagates to BOTH children.

    Read once from the parent environment so that
    `SYNTRIASS_SUITE=0x02 python3 verify_wire.py` actually exercises 0x02
    instead of being silently overwritten back to 0x01. Defaults to 0x01.
    """
    return os.environ.get("SYNTRIASS_SUITE", "0x01")


def identity_env(tool: str, role: str) -> dict[str, str]:
    suite = overlay_suite()
    client = derive_identity(tool, CLIENT_ED_SEED, CLIENT_ML_SEED)
    server = derive_identity(tool, SERVER_ED_SEED, SERVER_ML_SEED)
    if role == "client":
        return {
            "SYNTRIASS_SUITE": suite,
            "SYNTRIASS_ED25519_SEED_HEX": CLIENT_ED_SEED,
            "SYNTRIASS_MLDSA65_SEED_HEX": CLIENT_ML_SEED,
            "SYNTRIASS_PEER_ED25519_PUB_HEX": server["ed25519_public"],
            "SYNTRIASS_PEER_MLDSA65_PUB_HEX": server["mldsa65_public"],
        }
    if role == "server":
        return {
            "SYNTRIASS_SUITE": suite,
            "SYNTRIASS_ED25519_SEED_HEX": SERVER_ED_SEED,
            "SYNTRIASS_MLDSA65_SEED_HEX": SERVER_ML_SEED,
            "SYNTRIASS_PEER_ED25519_PUB_HEX": client["ed25519_public"],
            "SYNTRIASS_PEER_MLDSA65_PUB_HEX": client["mldsa65_public"],
        }
    raise ValueError(role)


# Canonical suite tokens -> the 1-byte suite id that travels in the frame header.
# Mirrors crypto::parse_suite_token for the two forms this harness emits.
_SUITE_TOKEN_TO_ID = {
    "0x01": 0x01, "1": 0x01, "768": 0x01, "nist768": 0x01,
    "0x02": 0x02, "2": 0x02, "1024": 0x02, "nist1024": 0x02,
}


def expected_suite_id() -> Optional[int]:
    return _SUITE_TOKEN_TO_ID.get(overlay_suite().strip().lower())


def wire_suite_id(wire: bytes) -> Optional[int]:
    """Extract the suite id the child actually emitted on the wire.

    Overlay frames are [body_len: 4 BE][suite_id: 1][tag: 1][payload...].
    Only the payload is encrypted; the suite id is in cleartext in the header,
    so the first captured frame is tamper-proof evidence of which suite the
    preloaded child negotiated -- independent of what we *think* we set.
    """
    if len(wire) < HDR_LEN + 1:
        return None
    return wire[HDR_LEN]


def free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class Relay:
    """Single-connection TCP relay that records all bytes in both directions."""

    def __init__(self, listen_port: int, target_port: int, tamper_first_client_chunk: bool = False):
        self.listen_port = listen_port
        self.target_port = target_port
        self.captured = bytearray()
        self.tamper_first_client_chunk = tamper_first_client_chunk
        self._tampered = False
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
                    if self.tamper_first_client_chunk and not self._tampered:
                        b = bytearray(chunk)
                        b[-1] ^= 0x01
                        chunk = bytes(b)
                        self._tampered = True
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


def run_scenario(
    *,
    lib: Optional[str],
    tool: Optional[str],
    preload_client: bool,
    preload_server: bool,
    tamper: bool = False,
) -> tuple[bytes, str, str]:
    """Returns (bytes_seen_on_wire, server_stdout, client_stdout)."""
    server_port = free_port()
    relay_port = free_port()

    relay = Relay(relay_port, server_port, tamper_first_client_chunk=tamper)
    relay.start()

    server_env = dict(os.environ)
    client_env = dict(os.environ)
    if tool:
        server_env.update(identity_env(tool, "server"))
        client_env.update(identity_env(tool, "client"))
    if lib and preload_server:
        server_env["LD_PRELOAD"] = lib
    if lib and preload_client:
        client_env["LD_PRELOAD"] = lib

    server = subprocess.Popen(
        [sys.executable, APP, "server", str(server_port)],
        env=server_env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    )
    time.sleep(0.5)  # let the server bind/listen

    client = subprocess.Popen(
        [sys.executable, APP, "client", str(relay_port), MARKER.decode()],
        env=client_env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    )

    try:
        client.wait(timeout=10)
        server.wait(timeout=10)
    except subprocess.TimeoutExpired:
        client.kill(); server.kill()
        raise

    server_out = server.stdout.read() if server.stdout else ""
    client_out = client.stdout.read() if client.stdout else ""
    time.sleep(0.2)
    return relay.wire_bytes(), server_out, client_out


def main() -> int:
    try:
        lib = find_lib()
        tool = find_identity_tool()
    except FileNotFoundError as e:
        print(f"FAIL: {e}")
        return 1

    suite_tok = overlay_suite()
    exp_id = expected_suite_id()
    exp_str = f"{exp_id:#04x}" if exp_id is not None else "UNKNOWN"
    print(f"== Propagating SYNTRIASS_SUITE={suite_tok!r} to both children "
          f"(expected wire suite id: {exp_str}) ==\n")

    print("== Scenario 1: BASELINE (no overlay) ==")
    wire, out, _client = run_scenario(
        lib=None, tool=None, preload_client=False, preload_server=False
    )
    print(out.strip())
    if MARKER not in wire:
        print("FAIL: baseline did not expose plaintext on the wire (test setup broken)")
        return 1
    print(f"OK: plaintext marker visible on wire ({len(wire)} bytes captured)\n")

    print("== Scenario 2: OVERLAY (LD_PRELOAD both ends) ==")
    wire, out, client = run_scenario(
        lib=lib, tool=tool, preload_client=True, preload_server=True
    )
    print(out.strip())
    print(client.strip())
    if MARKER in wire:
        print("FAIL: marker LEAKED on the wire under overlay")
        return 1
    if MARKER.decode() not in out:
        print("FAIL: server did not receive correct plaintext under overlay")
        return 1
    seen_id = wire_suite_id(wire)
    seen_str = f"{seen_id:#04x}" if seen_id is not None else "<none>"
    print(f"   wire suite id (cleartext frame header, what the child actually "
          f"negotiated): {seen_str}")
    if exp_id is not None:
        if seen_id != exp_id:
            print(f"FAIL: child negotiated suite {seen_str}, but the parent "
                  f"requested {exp_id:#04x} -- suite was not propagated")
            return 1
        print(f"   confirmed: child used the parent's suite {exp_id:#04x}, "
              f"not a hardcoded default")
    print(f"OK: wire is opaque ({len(wire)} bytes, no marker) AND server saw plaintext\n")

    print("== Scenario 3: TAMPERED AUTHENTICATED HANDSHAKE ==")
    wire, out, client = run_scenario(
        lib=lib, tool=tool, preload_client=True, preload_server=True, tamper=True
    )
    print(out.strip())
    print(client.strip())
    if MARKER in out.encode():
        print("FAIL: server accepted plaintext after tampered handshake")
        return 1
    if MARKER in wire:
        print("FAIL: application marker reached wire after tampered handshake")
        return 1
    print("OK: tampered handshake failed closed before application data\n")

    print("== Scenario 4: UNAUTHENTICATED CLIENT REJECTED ==")
    wire, out, client = run_scenario(
        lib=lib, tool=tool, preload_client=False, preload_server=True
    )
    print(out.strip())
    print(client.strip())
    if MARKER.decode() in out:
        print("FAIL: preloaded server delivered unauthenticated plaintext to app")
        return 1
    if MARKER not in wire:
        print("FAIL: unauthenticated client scenario did not send baseline marker")
        return 1
    print("OK: server rejected unauthenticated plaintext instead of delivering it\n")

    print("ALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
