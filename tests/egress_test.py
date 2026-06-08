#!/usr/bin/env python3
"""Alternate-egress fail-closed test for Syntriass overlay."""
import errno
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

from verify_wire import find_identity_tool, find_lib, free_port, identity_env

HERE = Path(__file__).resolve().parent
SELF = str(Path(__file__).resolve())
HOST = "127.0.0.1"

HELLO = b"EGRESS_NORMAL_HELLO"
DONE = b"EGRESS_NORMAL_DONE"
SENDTO_MARKER = b"PLAINTEXT_SENDTO_BYPASS_MARKER"
SENDFILE_MARKER = b"PLAINTEXT_SENDFILE_BYPASS_MARKER"
UDP_MARKER = b"UDP_SENDTO_ALLOWED"
FILE_MARKER = b"REGULAR_SENDFILE_ALLOWED"


def recv_exact(sock: socket.socket, n: int) -> bytes:
    out = bytearray()
    while len(out) < n:
        chunk = sock.recv(n - len(out))
        if not chunk:
            raise ConnectionError(f"peer closed after {len(out)}/{n} bytes")
        out.extend(chunk)
    return bytes(out)


class Relay:
    def __init__(self, listen_port: int, target_port: int):
        self.listen_port = listen_port
        self.target_port = target_port
        self.captured = bytearray()
        self._lock = threading.Lock()
        self._srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._srv.bind((HOST, listen_port))
        self._srv.listen(1)
        self._thread = threading.Thread(target=self._serve, daemon=True)

    def start(self) -> None:
        self._thread.start()

    def join(self, timeout: float) -> None:
        self._thread.join(timeout=timeout)

    def _pump(self, src: socket.socket, dst: socket.socket, record: bool) -> None:
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

    def _serve(self) -> None:
        client, _ = self._srv.accept()
        upstream = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        upstream.connect((HOST, self.target_port))
        t1 = threading.Thread(target=self._pump, args=(client, upstream, True), daemon=True)
        t2 = threading.Thread(target=self._pump, args=(upstream, client, False), daemon=True)
        t1.start()
        t2.start()
        t1.join()
        t2.join()
        client.close()
        upstream.close()
        self._srv.close()

    def wire(self) -> bytes:
        with self._lock:
            return bytes(self.captured)


def assert_errno(label: str, expected: int, fn) -> None:
    try:
        fn()
    except OSError as exc:
        print(f"[client] {label}_FAIL errno={exc.errno}", flush=True)
        if exc.errno != expected:
            raise
        return
    raise AssertionError(f"{label} unexpectedly succeeded")


def regular_sendfile_passes() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        src_path = Path(tmp) / "src.bin"
        dst_path = Path(tmp) / "dst.bin"
        src_path.write_bytes(FILE_MARKER)
        with src_path.open("rb") as src, dst_path.open("wb") as dst:
            sent = os.sendfile(dst.fileno(), src.fileno(), 0, len(FILE_MARKER))
        if sent != len(FILE_MARKER) or dst_path.read_bytes() != FILE_MARKER:
            raise AssertionError("regular sendfile pass-through failed")
    print(f"[client] REGULAR_SENDFILE_OK bytes={len(FILE_MARKER)}", flush=True)


def udp_sendto_passes() -> None:
    rx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    rx.bind((HOST, 0))
    rx.settimeout(5)
    tx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sent = tx.sendto(UDP_MARKER, (HOST, rx.getsockname()[1]))
    got, _ = rx.recvfrom(1024)
    tx.close()
    rx.close()
    if sent != len(UDP_MARKER) or got != UDP_MARKER:
        raise AssertionError("UDP sendto pass-through failed")
    print(f"[client] UDP_SENDTO_OK bytes={sent}", flush=True)


def role_server(port: int) -> int:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((HOST, port))
    srv.listen(1)
    print(f"[server] listening {port}", flush=True)
    conn, _ = srv.accept()
    first = recv_exact(conn, len(HELLO))
    conn.sendall(first)
    second = recv_exact(conn, len(DONE))
    conn.sendall(second)
    conn.close()
    srv.close()
    print(f"[server] received {first.decode()}", flush=True)
    print(f"[server] received {second.decode()}", flush=True)
    return 0


def role_client(port: int) -> int:
    regular_sendfile_passes()
    udp_sendto_passes()

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(10)
    sock.connect((HOST, port))
    sock.sendall(HELLO)
    if recv_exact(sock, len(HELLO)) != HELLO:
        print("[client] HELLO echo mismatch", flush=True)
        return 1

    assert_errno(
        "SENDTO_STREAM",
        errno.EOPNOTSUPP,
        lambda: sock.sendto(SENDTO_MARKER, (HOST, port)),
    )

    with tempfile.NamedTemporaryFile() as tmp:
        tmp.write(SENDFILE_MARKER)
        tmp.flush()
        tmp.seek(0)
        assert_errno(
            "SENDFILE_STREAM",
            errno.EOPNOTSUPP,
            lambda: os.sendfile(sock.fileno(), tmp.fileno(), 0, len(SENDFILE_MARKER)),
        )

    sock.sendall(DONE)
    if recv_exact(sock, len(DONE)) != DONE:
        print("[client] DONE echo mismatch", flush=True)
        return 1
    sock.close()
    print("[client] NORMAL_STREAM_STILL_OK", flush=True)
    return 0


def run_orchestrator() -> int:
    lib = find_lib()
    tool = find_identity_tool()
    server_port = free_port()
    relay_port = free_port()
    relay = Relay(relay_port, server_port)
    relay.start()

    server_env = dict(os.environ)
    server_env.update(identity_env(tool, "server"))
    server_env["LD_PRELOAD"] = lib
    client_env = dict(os.environ)
    client_env.update(identity_env(tool, "client"))
    client_env["LD_PRELOAD"] = lib

    server = subprocess.Popen(
        [sys.executable, SELF, "server", str(server_port)],
        env=server_env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    time.sleep(0.5)
    client = subprocess.Popen(
        [sys.executable, SELF, "client", str(relay_port)],
        env=client_env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )

    try:
        client.wait(timeout=20)
        server.wait(timeout=20)
    except subprocess.TimeoutExpired:
        client.kill()
        server.kill()
        print("FAIL: egress test timed out")
        return 1
    relay.join(timeout=5)

    server_out = server.stdout.read() if server.stdout else ""
    client_out = client.stdout.read() if client.stdout else ""
    print(client_out.strip())
    print(server_out.strip())

    wire = relay.wire()
    markers = [SENDTO_MARKER, SENDFILE_MARKER]
    leaked = [m for m in markers if m in wire]
    print(f"stream wire bytes={len(wire)} marker_present={bool(leaked)}")

    if client.returncode != 0 or server.returncode != 0:
        print(f"FAIL: client rc={client.returncode}, server rc={server.returncode}")
        return 1
    if leaked:
        print("FAIL: plaintext marker leaked on stream wire")
        return 1
    if len(wire) == 0:
        print("FAIL: relay capture was empty")
        return 1
    for required in (
        "SENDTO_STREAM_FAIL errno=95",
        "SENDFILE_STREAM_FAIL errno=95",
        "REGULAR_SENDFILE_OK",
        "UDP_SENDTO_OK",
        "NORMAL_STREAM_STILL_OK",
    ):
        if required not in client_out:
            print(f"FAIL: missing client proof line: {required}")
            return 1

    print("OK: tracked stream sendto/sendfile failed closed")
    print("OK: non-stream/non-socket operations passed through")
    print("OK: relay captured nonzero bytes and no plaintext marker")
    return 0


def main() -> int:
    if len(sys.argv) == 1:
        return run_orchestrator()
    if sys.argv[1] == "server":
        return role_server(int(sys.argv[2]))
    if sys.argv[1] == "client":
        return role_client(int(sys.argv[2]))
    print(f"unknown role: {sys.argv[1]}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
