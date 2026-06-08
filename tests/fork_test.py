#!/usr/bin/env python3
"""Fork-inherited fd regression test for Syntriass overlay.

The relay is not preloaded. It records client->server overlay frames, so the
test can prove the forked child did not contribute an encrypted Data record on
the inherited connection.
"""
import os
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

from verify_wire import find_identity_tool, find_lib, free_port, identity_env

HERE = Path(__file__).resolve().parent
SELF = str(Path(__file__).resolve())
HOST = "127.0.0.1"
HDR_LEN = 4
TYPE_DATA = 3

PARENT_ONE = b"PARENT_MESSAGE_BEFORE_FORK"
PARENT_TWO = b"PARENT_MESSAGE_AFTER_FORK"
CHILD_BAD = b"CHILD_INHERITED_FD_MUST_NOT_SEAL"
FRESH_CHILD = b"FRESH_CHILD_CONNECTION_OK"


def recv_exact(sock: socket.socket, n: int) -> bytes:
    out = bytearray()
    while len(out) < n:
        chunk = sock.recv(n - len(out))
        if not chunk:
            raise ConnectionError(f"peer closed after {len(out)}/{n} bytes")
        out.extend(chunk)
    return bytes(out)


def data_record_count(wire: bytes) -> int:
    count = 0
    offset = 0
    while offset + HDR_LEN <= len(wire):
        body_len = int.from_bytes(wire[offset:offset + HDR_LEN], "big")
        if body_len < 2 or offset + HDR_LEN + body_len > len(wire):
            break
        tag = wire[offset + HDR_LEN + 1]
        if tag == TYPE_DATA:
            count += 1
        offset += HDR_LEN + body_len
    return count


class MultiRelay:
    def __init__(self, listen_port: int, target_port: int, conns: int):
        self.listen_port = listen_port
        self.target_port = target_port
        self.captures = [bytearray() for _ in range(conns)]
        self._conns = conns
        self._lock = threading.Lock()
        self._srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._srv.bind((HOST, listen_port))
        self._srv.listen(conns)
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._workers = []

    def start(self) -> None:
        self._thread.start()

    def join(self, timeout: float) -> None:
        self._thread.join(timeout=timeout)
        for t in self._workers:
            t.join(timeout=timeout)

    def _pump(self, src: socket.socket, dst: socket.socket, index: int, record: bool) -> None:
        try:
            while True:
                chunk = src.recv(4096)
                if not chunk:
                    break
                if record:
                    with self._lock:
                        self.captures[index].extend(chunk)
                dst.sendall(chunk)
        except OSError:
            pass
        finally:
            try:
                dst.shutdown(socket.SHUT_WR)
            except OSError:
                pass

    def _handle(self, client: socket.socket, index: int) -> None:
        upstream = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        upstream.connect((HOST, self.target_port))
        t1 = threading.Thread(target=self._pump, args=(client, upstream, index, True), daemon=True)
        t2 = threading.Thread(target=self._pump, args=(upstream, client, index, False), daemon=True)
        t1.start()
        t2.start()
        t1.join()
        t2.join()
        client.close()
        upstream.close()

    def _serve(self) -> None:
        for index in range(self._conns):
            client, _ = self._srv.accept()
            t = threading.Thread(target=self._handle, args=(client, index), daemon=True)
            t.start()
            self._workers.append(t)
        self._srv.close()

    def wire(self, index: int) -> bytes:
        with self._lock:
            return bytes(self.captures[index])


def role_server(port: int) -> int:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((HOST, port))
    srv.listen(2)
    print(f"[server] listening {port}", flush=True)

    conn, _ = srv.accept()
    got = []
    for expected in (PARENT_ONE, PARENT_TWO):
        data = recv_exact(conn, len(expected))
        got.append(data)
        conn.sendall(data)
    conn.close()

    conn, _ = srv.accept()
    fresh = recv_exact(conn, len(FRESH_CHILD))
    conn.sendall(fresh)
    conn.close()
    srv.close()

    for item in got:
        print(f"[server] received {item.decode()}", flush=True)
    print(f"[server] received {fresh.decode()}", flush=True)
    return 0


def role_client(port: int) -> int:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(10)
    sock.connect((HOST, port))
    sock.sendall(PARENT_ONE)
    if recv_exact(sock, len(PARENT_ONE)) != PARENT_ONE:
        print("[client] parent before echo mismatch", flush=True)
        return 1

    read_fd, write_fd = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(read_fd)
        try:
            sock.sendall(CHILD_BAD)
            msg = b"CHILD_INHERITED_UNEXPECTED_SUCCESS"
        except OSError as exc:
            msg = f"CHILD_INHERITED_FAIL errno={exc.errno}".encode("ascii")
        os.write(write_fd, msg)
        os.close(write_fd)
        os._exit(0)

    os.close(write_fd)
    child_report = os.read(read_fd, 1024).decode("ascii")
    os.close(read_fd)
    _, child_status = os.waitpid(pid, 0)
    print(f"[client] {child_report} status={child_status}", flush=True)

    sock.sendall(PARENT_TWO)
    if recv_exact(sock, len(PARENT_TWO)) != PARENT_TWO:
        print("[client] parent after echo mismatch", flush=True)
        return 1
    print("[client] PARENT_AFTER_OK", flush=True)
    sock.close()

    read_fd, write_fd = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(read_fd)
        try:
            fresh = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            fresh.settimeout(10)
            fresh.connect((HOST, port))
            fresh.sendall(FRESH_CHILD)
            ok = recv_exact(fresh, len(FRESH_CHILD)) == FRESH_CHILD
            fresh.close()
            msg = b"FRESH_CHILD_OK" if ok else b"FRESH_CHILD_ECHO_MISMATCH"
        except OSError as exc:
            msg = f"FRESH_CHILD_FAIL errno={exc.errno}".encode("ascii")
        os.write(write_fd, msg)
        os.close(write_fd)
        os._exit(0)

    os.close(write_fd)
    fresh_report = os.read(read_fd, 1024).decode("ascii")
    os.close(read_fd)
    _, fresh_status = os.waitpid(pid, 0)
    print(f"[client] {fresh_report} status={fresh_status}", flush=True)

    if child_report != "CHILD_INHERITED_FAIL errno=32":
        return 1
    if fresh_report != "FRESH_CHILD_OK":
        return 1
    return 0


def run_orchestrator() -> int:
    lib = find_lib()
    tool = find_identity_tool()
    server_port = free_port()
    relay_port = free_port()
    relay = MultiRelay(relay_port, server_port, 2)
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
        print("FAIL: fork test timed out")
        return 1
    relay.join(timeout=5)

    server_out = server.stdout.read() if server.stdout else ""
    client_out = client.stdout.read() if client.stdout else ""
    print(client_out.strip())
    print(server_out.strip())

    conn1_wire = relay.wire(0)
    conn2_wire = relay.wire(1)
    conn1_data = data_record_count(conn1_wire)
    conn2_data = data_record_count(conn2_wire)
    print(f"conn1 wire bytes={len(conn1_wire)} data_records={conn1_data}")
    print(f"conn2 wire bytes={len(conn2_wire)} data_records={conn2_data}")

    if client.returncode != 0 or server.returncode != 0:
        print(f"FAIL: client rc={client.returncode}, server rc={server.returncode}")
        return 1
    if CHILD_BAD.decode() in server_out:
        print("FAIL: server received inherited-child plaintext")
        return 1
    if conn1_data != 2 or conn2_data != 1:
        print("FAIL: unexpected Data record count; child may have sealed on inherited fd")
        return 1
    if len(conn1_wire) == 0 or len(conn2_wire) == 0:
        print("FAIL: relay capture was empty")
        return 1

    print("OK: child inherited fd failed closed; parent and fresh child succeeded")
    print("OK: wire confirms inherited child contributed zero Data records")
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
