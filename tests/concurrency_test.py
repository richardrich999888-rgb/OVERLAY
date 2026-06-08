#!/usr/bin/env python3
"""Concurrency stress test for the Syntriass overlay.

The single-connection wire test (verify_wire.py) is the most forgiving possible
load: one client, one server, one short-lived connection. It proves nothing
about contention on the process-global `REGISTRY` mutex, which is held across
blocking socket I/O inside the interceptor.

This script applies the load that single-connection cannot:

    * One SERVER process (overlay preloaded) that accepts many connections and
      services each on its own thread.
    * One CLIENT process (overlay preloaded) that opens N connections
      concurrently -- released together via a barrier to maximize contention --
      each doing a send -> recv round trip with a DISTINCT payload.

A hard wall-clock timeout wraps the whole run, so the suspected
"mutex-held-across-blocking-I/O" failure surfaces as a TIMEOUT rather than an
infinite hang. Each worker records its completion to a per-side done-file, so
even on timeout we can report exactly how many connections completed vs hung.

Roles (the preloaded children re-exec this same file):
    concurrency_test.py server <port> <n> <donefile>
    concurrency_test.py client <port> <n> <donefile>
    concurrency_test.py                 # orchestrator (no preload)

Exit code 0 = all N round trips completed with correct echoes at every N tried.
"""
import os
import shutil
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent

PAYLOAD_LEN = 64
WALL_TIMEOUT_S = 20.0
CONNECT_TIMEOUT_S = 15.0

CLIENT_ED_SEED = "11" * 32
CLIENT_ML_SEED = "22" * 32
SERVER_ED_SEED = "33" * 32
SERVER_ML_SEED = "44" * 32


# --------------------------------------------------------------------------- #
# Shared helpers
# --------------------------------------------------------------------------- #
def payload_for(i: int) -> bytes:
    """Fixed-length, per-connection-distinct payload."""
    return f"CONN{i:05d}".encode("ascii").ljust(PAYLOAD_LEN, b".")


def conn_id_of(payload: bytes) -> str:
    return payload[:10].rstrip(b".").decode("ascii", errors="replace")


def recv_exact(sock: socket.socket, n: int) -> bytes:
    """Read exactly n bytes or raise; tolerates the overlay's record framing."""
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError(f"peer closed after {len(buf)}/{n} bytes")
        buf.extend(chunk)
    return bytes(buf)


def record_done(donefile: str, ident: str) -> None:
    # Append-only; one line per completed connection. Robust to partial runs.
    with open(donefile, "a", buffering=1) as f:
        f.write(ident + "\n")


# --------------------------------------------------------------------------- #
# Server role (overlay preloaded)
# --------------------------------------------------------------------------- #
def handle_conn(conn: socket.socket, donefile: str) -> None:
    try:
        data = recv_exact(conn, PAYLOAD_LEN)
        conn.sendall(data)  # exact echo
        record_done(donefile, "server:" + conn_id_of(data))
    except OSError:
        pass
    finally:
        try:
            conn.shutdown(socket.SHUT_WR)
        except OSError:
            pass
        conn.close()


def run_server(port: int, n: int, donefile: str) -> int:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(max(128, n))
    print(f"[server] listening on 127.0.0.1:{port} for {n} connections", flush=True)
    threads = []
    for _ in range(n):
        conn, _ = srv.accept()
        t = threading.Thread(target=handle_conn, args=(conn, donefile), daemon=True)
        t.start()
        threads.append(t)
    for t in threads:
        t.join()
    srv.close()
    print("[server] all worker threads joined", flush=True)
    return 0


# --------------------------------------------------------------------------- #
# Client role (overlay preloaded)
# --------------------------------------------------------------------------- #
def run_client(port: int, n: int, donefile: str) -> int:
    barrier = threading.Barrier(n)
    results: list[bool] = [False] * n

    def worker(i: int) -> None:
        payload = payload_for(i)
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect(("127.0.0.1", port))
            barrier.wait()  # release all connections together -> peak contention
            s.sendall(payload)
            echo = recv_exact(s, PAYLOAD_LEN)
            s.close()
            if echo == payload:
                results[i] = True
                record_done(donefile, "client:" + conn_id_of(payload))
        except OSError as e:
            print(f"[client] conn {i} failed: {e}", flush=True)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    ok = sum(results)
    print(f"[client] {ok}/{n} round trips verified", flush=True)
    return 0 if ok == n else 1


# --------------------------------------------------------------------------- #
# Orchestrator (no preload)
# --------------------------------------------------------------------------- #
def find_lib() -> str:
    for name in ("libsyntriass_overlay.so",):
        p = ROOT / "target" / "release" / name
        if p.exists():
            return str(p)
    raise FileNotFoundError("built library not found; run `cargo build --release` first")


def find_identity_tool() -> str:
    p = ROOT / "target" / "release" / "syntriass-identity"
    if p.exists():
        return str(p)
    raise FileNotFoundError("identity helper not found; run `cargo build --release` first")


def derive_identity(tool: str, ed_seed: str, ml_seed: str) -> dict:
    out = subprocess.check_output([tool, ed_seed, ml_seed], text=True)
    result = {}
    for line in out.splitlines():
        key, value = line.split("=", 1)
        result[key] = value
    return result


def suite() -> str:
    return os.environ.get("SYNTRIASS_SUITE", "0x01")


def identity_env(tool: str, role: str) -> dict:
    client = derive_identity(tool, CLIENT_ED_SEED, CLIENT_ML_SEED)
    server = derive_identity(tool, SERVER_ED_SEED, SERVER_ML_SEED)
    base = {"SYNTRIASS_SUITE": suite()}
    if role == "client":
        base.update({
            "SYNTRIASS_ED25519_SEED_HEX": CLIENT_ED_SEED,
            "SYNTRIASS_MLDSA65_SEED_HEX": CLIENT_ML_SEED,
            "SYNTRIASS_PEER_ED25519_PUB_HEX": server["ed25519_public"],
            "SYNTRIASS_PEER_MLDSA65_PUB_HEX": server["mldsa65_public"],
        })
    elif role == "server":
        base.update({
            "SYNTRIASS_ED25519_SEED_HEX": SERVER_ED_SEED,
            "SYNTRIASS_MLDSA65_SEED_HEX": SERVER_ML_SEED,
            "SYNTRIASS_PEER_ED25519_PUB_HEX": client["ed25519_public"],
            "SYNTRIASS_PEER_MLDSA65_PUB_HEX": client["mldsa65_public"],
        })
    else:
        raise ValueError(role)
    return base


def free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def count_lines(path: Path) -> int:
    if not path.exists():
        return 0
    with open(path, "r") as f:
        return sum(1 for line in f if line.strip())


def dump_with_pyspy(pids: list, label: str) -> None:
    if not shutil.which("py-spy"):
        print(f"[{label}] py-spy not available; relying on done-file counts", flush=True)
        return
    for pid in pids:
        print(f"[{label}] py-spy dump pid={pid}", flush=True)
        try:
            subprocess.run(["py-spy", "dump", "--pid", str(pid)], timeout=15)
        except Exception as e:  # noqa: BLE001
            print(f"[{label}] py-spy dump failed for {pid}: {e}", flush=True)


def run_round(n: int, lib: str, tool: str, workdir: Path) -> bool:
    """Run one N-connection round. Returns True iff all N completed correctly."""
    print(f"\n== Concurrency round: N={n} (wall timeout {WALL_TIMEOUT_S:.0f}s) ==", flush=True)
    port = free_port()
    server_done = workdir / f"server_done_{n}.log"
    client_done = workdir / f"client_done_{n}.log"
    for p in (server_done, client_done):
        if p.exists():
            p.unlink()

    server_env = dict(os.environ)
    server_env.update(identity_env(tool, "server"))
    server_env["LD_PRELOAD"] = lib

    client_env = dict(os.environ)
    client_env.update(identity_env(tool, "client"))
    client_env["LD_PRELOAD"] = lib

    me = str(Path(__file__).resolve())
    server = subprocess.Popen(
        [sys.executable, me, "server", str(port), str(n), str(server_done)],
        env=server_env,
    )
    time.sleep(0.5)  # let the server bind/listen
    client = subprocess.Popen(
        [sys.executable, me, "client", str(port), str(n), str(client_done)],
        env=client_env,
    )

    deadline = time.time() + WALL_TIMEOUT_S
    timed_out = False
    try:
        remaining = deadline - time.time()
        client.wait(timeout=max(0.1, remaining))
        remaining = deadline - time.time()
        server.wait(timeout=max(0.1, remaining))
    except subprocess.TimeoutExpired:
        timed_out = True

    client_ok = count_lines(client_done)
    server_ok = count_lines(server_done)

    if timed_out:
        print(f"!! TIMEOUT after {WALL_TIMEOUT_S:.0f}s -- run did not complete", flush=True)
        print(f"   client verified completions: {client_ok}/{n}", flush=True)
        print(f"   server echo completions:     {server_ok}/{n}", flush=True)
        print(f"   stuck connections (client side): {n - client_ok}/{n}", flush=True)
        dump_with_pyspy([p.pid for p in (client, server) if p.poll() is None],
                        f"N={n}")
        for p in (client, server):
            if p.poll() is None:
                p.kill()
        try:
            client.wait(timeout=5)
            server.wait(timeout=5)
        except subprocess.TimeoutExpired:
            pass
        print(f"== RESULT N={n}: DEADLOCK/TIMEOUT "
              f"({client_ok}/{n} client, {server_ok}/{n} server) ==", flush=True)
        return False

    rc_client = client.returncode
    rc_server = server.returncode
    print(f"   client rc={rc_client}, verified {client_ok}/{n}", flush=True)
    print(f"   server rc={rc_server}, echoed   {server_ok}/{n}", flush=True)
    passed = rc_client == 0 and client_ok == n and server_ok == n
    print(f"== RESULT N={n}: {'PASS' if passed else 'FAIL'} "
          f"({client_ok}/{n} completed) ==", flush=True)
    return passed


def orchestrate() -> int:
    try:
        lib = find_lib()
        tool = find_identity_tool()
    except FileNotFoundError as e:
        print(f"FAIL: {e}")
        return 1

    print(f"overlay lib:    {lib}")
    print(f"identity tool:  {tool}")
    print(f"suite:          {suite()}")

    workdir = ROOT / "target" / "concurrency"
    workdir.mkdir(parents=True, exist_ok=True)

    if not run_round(16, lib, tool, workdir):
        print("\nFINAL: concurrency FAILED at N=16 (see timeout/deadlock report above)")
        return 1

    # N=16 clean -> escalate once to N=64.
    if not run_round(64, lib, tool, workdir):
        print("\nFINAL: concurrency PASSED at N=16 but FAILED at N=64")
        return 1

    print("\nFINAL: concurrency PASSED at N=16 and N=64")
    return 0


def main() -> int:
    if len(sys.argv) == 1:
        return orchestrate()
    role = sys.argv[1]
    if role == "server":
        return run_server(int(sys.argv[2]), int(sys.argv[3]), sys.argv[4])
    if role == "client":
        return run_client(int(sys.argv[2]), int(sys.argv[3]), sys.argv[4])
    print(f"unknown role: {role}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
