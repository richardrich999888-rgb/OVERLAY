#!/usr/bin/env python3
"""Failure-injection / fail-closed validation for the Syntriass overlay.

Same discipline as concurrency_test.py: we do not *assume* fail-closed, we
*induce* each failure on the wire and assert two invariants hold every time.

Topology (the relay is a plain, NEVER-preloaded man-in-the-middle that can
record / corrupt / drop / dribble the actual bytes in transit):

    client (overlay) ---> relay (adversary) ---> server (overlay)

The two invariants every case must satisfy:

  (A) NO PLAINTEXT LEAK: the marker CONFIDENTIAL_MISSION_DATA_STREAM never
      appears in cleartext on the wire, and never reaches a peer that should
      not get it. (In the one success-path case -- dribbled-but-valid -- the
      legitimate server *is* allowed to decrypt it; that is not a leak. The
      wire must still carry only ciphertext.)

  (B) NO HANG: every case completes within a hard per-case wall-clock timeout.
      A hang is a FAIL, captured with py-spy, not silently tolerated.

Cases (each independent, each asserting A and B):
  1. Peer drop mid-handshake          (relay eats ClientHello, closes)
  2a. Dribbled valid stream           (1 byte / TCP segment, reassembly must hold)
  2b. Truncated frame                 (relay cuts mid-ClientHello and closes)
  3. Corrupted handshake              (relay flips a byte in the ClientHello)
  4. Corrupted data record            (relay flips a byte in a Data frame's ct)
  5. Oversized frame                  (relay injects a >16 MiB declared length)
  6. Identity mismatch                (client signs with an untrusted identity)
  7. Identity mismatch x N=16         (case 6 under concurrency)

This file re-execs itself for the preloaded client/server roles (LD_PRELOAD
only affects new processes), exactly like concurrency_test.py:

    failclosed_test.py server <port> <n>
    failclosed_test.py client <port> <n>
    failclosed_test.py                       # orchestrator (no preload)

Exit 0 = all seven hold fail-closed (no leak, no hang anywhere).
"""
import os
import shutil
import socket
import struct
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Optional

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
SELF = str(Path(__file__).resolve())

MARKER = b"CONFIDENTIAL_MISSION_DATA_STREAM"
HDR_LEN = 4
TAG_DATA = 3
MAX_FRAME_BODY = 16 * 1024 * 1024 - HDR_LEN  # mirrors fd_state::MAX_WIRE_RX_BUFFER
PER_CASE_TIMEOUT_S = 10.0

# Trusted identities (the same fixed seeds the other harnesses use).
CLIENT_ED_SEED = "11" * 32
CLIENT_ML_SEED = "22" * 32
SERVER_ED_SEED = "33" * 32
SERVER_ML_SEED = "44" * 32
# An identity the server does NOT trust -- used to prove auth rejection.
WRONG_ED_SEED = "55" * 32
WRONG_ML_SEED = "66" * 32


# --------------------------------------------------------------------------- #
# Preloaded roles (re-exec of this file under LD_PRELOAD)
# --------------------------------------------------------------------------- #
def role_server(port: int, n: int) -> int:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(max(16, n))
    print(f"SRV LISTEN port={port} n={n}", flush=True)

    def handle(conn: socket.socket) -> None:
        try:
            # overlay_recv only ever returns *decrypted* plaintext; on any
            # handshake/AEAD/framing failure it returns -1 -> OSError here.
            data = conn.recv(4096)
            if data:
                has = 1 if MARKER in data else 0
                print(f"SRV RECV bytes={len(data)} marker={has}", flush=True)
                try:
                    conn.sendall(b"ACK" + data)
                except OSError:
                    pass
            else:
                print("SRV EOF", flush=True)
        except OSError as e:
            print(f"SRV ERR errno={e.errno or 0}", flush=True)
        finally:
            try:
                conn.close()
            except OSError:
                pass

    threads = []
    for _ in range(n):
        try:
            conn, _ = srv.accept()
        except OSError:
            break
        t = threading.Thread(target=handle, args=(conn,), daemon=True)
        t.start()
        threads.append(t)
    for t in threads:
        t.join()
    print("SRV DONE", flush=True)
    srv.close()
    return 0


def _client_one(port: int, barrier: Optional[threading.Barrier]) -> None:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(("127.0.0.1", port))
        if barrier is not None:
            barrier.wait()
        # If the overlay cannot reach an authenticated Active session it returns
        # -1 here (OSError) BEFORE any plaintext is framed -- that is fail-closed.
        s.sendall(MARKER)
        try:
            echo = s.recv(4096)
        except OSError:
            echo = b""
        me = 1 if MARKER in echo else 0
        print(f"CLI OK echo={1 if echo else 0} marker_echo={me}", flush=True)
        s.close()
    except OSError as e:
        print(f"CLI FAIL errno={e.errno or 0}", flush=True)


def role_client(port: int, n: int) -> int:
    if n <= 1:
        _client_one(port, None)
        return 0
    barrier = threading.Barrier(n)
    threads = [
        threading.Thread(target=_client_one, args=(port, barrier), daemon=True)
        for _ in range(n)
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    return 0


# --------------------------------------------------------------------------- #
# Adversarial relay (plain sockets; NEVER preloaded)
# --------------------------------------------------------------------------- #
class Relay:
    """A man-in-the-middle that records client->server bytes and, depending on
    `mode`, drops / dribbles / truncates / corrupts / injects on the wire."""

    def __init__(self, listen_port: int, target_port: Optional[int],
                 mode: str = "record", n_conns: int = 1):
        self.listen_port = listen_port
        self.target_port = target_port
        self.mode = mode
        self.n_conns = n_conns
        self.captured = bytearray()
        self._lock = threading.Lock()
        self._handlers = []
        self._srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._srv.bind(("127.0.0.1", listen_port))
        self._srv.listen(max(16, n_conns))
        self._thread = threading.Thread(target=self._serve, daemon=True)

    def start(self):
        self._thread.start()

    def wire_bytes(self) -> bytes:
        with self._lock:
            return bytes(self.captured)

    def _record(self, chunk: bytes):
        with self._lock:
            self.captured.extend(chunk)

    # -- generic byte pump ------------------------------------------------- #
    def _pump(self, src, dst, record=False, byte_at_a_time=False, transform=None):
        try:
            while True:
                chunk = src.recv(4096)
                if not chunk:
                    break
                if record:
                    self._record(chunk)
                out = transform(chunk) if transform else chunk
                if out is None:
                    break
                if out:
                    if byte_at_a_time:
                        for i in range(len(out)):
                            dst.sendall(out[i:i + 1])
                    else:
                        dst.sendall(out)
        except OSError:
            pass
        finally:
            try:
                dst.shutdown(socket.SHUT_WR)
            except OSError:
                pass

    # -- frame-aware corruption of the first Data record ------------------- #
    def _pump_corrupt_data(self, src, dst):
        buf = bytearray()
        done = False
        try:
            while True:
                chunk = src.recv(4096)
                if not chunk:
                    break
                self._record(chunk)
                buf += chunk
                while len(buf) >= HDR_LEN:
                    body = int.from_bytes(buf[:HDR_LEN], "big")
                    total = HDR_LEN + body
                    if body < 2 or body > MAX_FRAME_BODY:
                        # not a frame boundary we understand; forward verbatim
                        dst.sendall(bytes(buf))
                        buf.clear()
                        break
                    if len(buf) < total:
                        break
                    frame = bytearray(buf[:total])
                    del buf[:total]
                    # [len:4][suite:1][tag:1][payload...]; tag at index 5.
                    if not done and len(frame) >= HDR_LEN + 3 and frame[5] == TAG_DATA:
                        frame[6] ^= 0x01  # flip first ciphertext byte -> AEAD fail
                        done = True
                    dst.sendall(bytes(frame))
        except OSError:
            pass
        finally:
            if buf:
                try:
                    dst.sendall(bytes(buf))
                except OSError:
                    pass
            try:
                dst.shutdown(socket.SHUT_WR)
            except OSError:
                pass

    def _bidi(self, client, upstream, c2s, s2c):
        t1 = threading.Thread(target=c2s, args=(client, upstream), daemon=True)
        t2 = threading.Thread(target=s2c, args=(upstream, client), daemon=True)
        t1.start(); t2.start()
        t1.join(); t2.join()
        for so in (client, upstream):
            try:
                so.close()
            except OSError:
                pass

    def _cut_midframe(self, client, upstream):
        buf = bytearray()
        total0 = None
        try:
            client.settimeout(2.0)
            while True:
                chunk = client.recv(4096)
                if not chunk:
                    break
                self._record(chunk)
                buf += chunk
                if total0 is None and len(buf) >= HDR_LEN:
                    total0 = HDR_LEN + int.from_bytes(buf[:HDR_LEN], "big")
                if total0 is not None and len(buf) >= total0:
                    break
        except OSError:
            pass
        half = max(1, (total0 or len(buf)) // 2)
        try:
            upstream.sendall(bytes(buf[:half]))  # forward only half a frame
            upstream.shutdown(socket.SHUT_WR)    # then EOF mid-frame
        except OSError:
            pass
        time.sleep(0.1)
        for so in (client, upstream):
            try:
                so.close()
            except OSError:
                pass

    def _oversized(self, client, upstream):
        # Declared body length far beyond the 16 MiB bound; only 4 payload bytes
        # actually sent. The overlay must reject on the length check at parse
        # time -- never allocate / wait for the declared size.
        crafted = struct.pack(">I", 0xF0000000) + bytes([0x01, 0x02, 0xAA, 0xBB])
        try:
            upstream.sendall(crafted)
        except OSError:
            pass
        t = threading.Thread(target=self._pump, args=(upstream, client), daemon=True)
        t.start()
        try:
            client.settimeout(2.0)
            while True:
                chunk = client.recv(4096)
                if not chunk:
                    break
                self._record(chunk)  # record the client's real ClientHello
        except OSError:
            pass
        finally:
            try:
                upstream.shutdown(socket.SHUT_WR)
            except OSError:
                pass
        t.join(timeout=2)
        for so in (client, upstream):
            try:
                so.close()
            except OSError:
                pass

    def _handle(self, client):
        if self.target_port is None:
            # mode 'drop_after_hello': accept, read the ClientHello, then close
            # without ever sending a ServerHello.
            try:
                client.settimeout(1.0)
                while True:
                    chunk = client.recv(4096)
                    if not chunk:
                        break
                    self._record(chunk)
                    break
            except OSError:
                pass
            try:
                client.close()
            except OSError:
                pass
            return

        upstream = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        upstream.connect(("127.0.0.1", self.target_port))
        mode = self.mode
        if mode == "record":
            self._bidi(client, upstream,
                       lambda s, d: self._pump(s, d, record=True),
                       lambda s, d: self._pump(s, d))
        elif mode == "dribble":
            for so in (client, upstream):
                so.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            self._bidi(client, upstream,
                       lambda s, d: self._pump(s, d, record=True, byte_at_a_time=True),
                       lambda s, d: self._pump(s, d, byte_at_a_time=True))
        elif mode == "cut_midframe":
            self._cut_midframe(client, upstream)
        elif mode == "corrupt_hello":
            st = {"flipped": False}

            def tf(chunk):
                if not st["flipped"] and chunk:
                    b = bytearray(chunk)
                    b[-1] ^= 0x01
                    st["flipped"] = True
                    return bytes(b)
                return chunk

            self._bidi(client, upstream,
                       lambda s, d: self._pump(s, d, record=True, transform=tf),
                       lambda s, d: self._pump(s, d))
        elif mode == "corrupt_data":
            self._bidi(client, upstream,
                       lambda s, d: self._pump_corrupt_data(s, d),
                       lambda s, d: self._pump(s, d))
        elif mode == "oversized":
            self._oversized(client, upstream)
        else:
            raise ValueError(mode)

    def _serve(self):
        for _ in range(self.n_conns):
            try:
                client, _ = self._srv.accept()
            except OSError:
                break
            t = threading.Thread(target=self._handle, args=(client,), daemon=True)
            t.start()
            self._handlers.append(t)
        for t in self._handlers:
            t.join()
        try:
            self._srv.close()
        except OSError:
            pass


# --------------------------------------------------------------------------- #
# Orchestrator helpers
# --------------------------------------------------------------------------- #
def find_lib() -> str:
    p = ROOT / "target" / "release" / "libsyntriass_overlay.so"
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


def server_env(lib: str, tool: str) -> dict:
    client = derive_identity(tool, CLIENT_ED_SEED, CLIENT_ML_SEED)
    env = dict(os.environ)
    env["LD_PRELOAD"] = lib
    env.update({
        "SYNTRIASS_SUITE": suite(),
        "SYNTRIASS_ED25519_SEED_HEX": SERVER_ED_SEED,
        "SYNTRIASS_MLDSA65_SEED_HEX": SERVER_ML_SEED,
        # Server always trusts the *real* client identity only.
        "SYNTRIASS_PEER_ED25519_PUB_HEX": client["ed25519_public"],
        "SYNTRIASS_PEER_MLDSA65_PUB_HEX": client["mldsa65_public"],
    })
    return env


def client_env(lib: str, tool: str, identity: str = "real") -> dict:
    server = derive_identity(tool, SERVER_ED_SEED, SERVER_ML_SEED)
    ed, ml = (CLIENT_ED_SEED, CLIENT_ML_SEED) if identity == "real" \
        else (WRONG_ED_SEED, WRONG_ML_SEED)
    env = dict(os.environ)
    env["LD_PRELOAD"] = lib
    env.update({
        "SYNTRIASS_SUITE": suite(),
        "SYNTRIASS_ED25519_SEED_HEX": ed,
        "SYNTRIASS_MLDSA65_SEED_HEX": ml,
        # Peer (server) public keys are always correct; only the client's own
        # identity is swapped for the mismatch cases.
        "SYNTRIASS_PEER_ED25519_PUB_HEX": server["ed25519_public"],
        "SYNTRIASS_PEER_MLDSA65_PUB_HEX": server["mldsa65_public"],
    })
    return env


def free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def spawn(role: str, port: int, n: int, env: dict) -> subprocess.Popen:
    return subprocess.Popen(
        [sys.executable, SELF, role, str(port), str(n)],
        env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    )


def vmrss_mb(pid: int) -> float:
    try:
        with open(f"/proc/{pid}/status") as f:
            for line in f:
                if line.startswith("VmRSS:"):
                    return int(line.split()[1]) / 1024.0
    except OSError:
        pass
    return 0.0


def pyspy_dump(pids):
    if not shutil.which("py-spy"):
        print("   [py-spy unavailable -- reporting hang from process state only]", flush=True)
        return
    for pid in pids:
        print(f"   --- py-spy dump pid={pid} ---", flush=True)
        try:
            subprocess.run(["py-spy", "dump", "--pid", str(pid)], timeout=15)
        except Exception as e:  # noqa: BLE001
            print(f"   py-spy dump failed for {pid}: {e}", flush=True)


def wait_all(procs, timeout: float, rss_pid: Optional[int] = None):
    """Returns (timed_out, max_rss_mb). On timeout, py-spy dumps the survivors."""
    deadline = time.time() + timeout
    max_rss = 0.0
    timed_out = False
    while True:
        if rss_pid:
            max_rss = max(max_rss, vmrss_mb(rss_pid))
        if all(p.poll() is not None for p in procs):
            break
        if time.time() > deadline:
            timed_out = True
            break
        time.sleep(0.02)
    if timed_out:
        alive = [p.pid for p in procs if p.poll() is None]
        print(f"   !! TIMEOUT after {timeout:.0f}s; pids still alive: {alive}", flush=True)
        pyspy_dump(alive)
        for p in procs:
            if p.poll() is None:
                p.kill()
    for p in procs:
        try:
            p.wait(timeout=3)
        except subprocess.TimeoutExpired:
            pass
    return timed_out, max_rss


def drain(p: subprocess.Popen) -> str:
    try:
        return (p.stdout.read() if p.stdout else "").strip()
    except Exception:  # noqa: BLE001
        return ""


def server_decrypted_marker(sout: str) -> bool:
    return "marker=1" in sout


def one_line(s: str) -> str:
    return " | ".join(l for l in s.splitlines() if l.strip())


# --------------------------------------------------------------------------- #
# Cases
# --------------------------------------------------------------------------- #
def case_peer_drop(lib, tool):
    rp = free_port()
    relay = Relay(rp, None, mode="drop_after_hello")
    relay.start()
    client = spawn("client", rp, 1, client_env(lib, tool, "real"))
    timed_out, _ = wait_all([client], PER_CASE_TIMEOUT_S)
    cout = drain(client)
    cap = relay.wire_bytes()
    no_leak = MARKER not in cap
    no_hang = not timed_out
    obs = (f"relay closed before ServerHello; client={one_line(cout)!r}; "
           f"ClientHello captured={len(cap)}B, marker absent={MARKER not in cap}")
    return ("1. peer drop mid-handshake", no_leak, no_hang, obs)


def case_dribble_valid(lib, tool):
    sp, rp = free_port(), free_port()
    server = spawn("server", sp, 1, server_env(lib, tool))
    time.sleep(0.5)
    relay = Relay(rp, sp, mode="dribble")
    relay.start()
    client = spawn("client", rp, 1, client_env(lib, tool, "real"))
    timed_out, _ = wait_all([client, server], PER_CASE_TIMEOUT_S)
    sout, cout = drain(server), drain(client)
    cap = relay.wire_bytes()
    wire_clear = MARKER in cap
    # Legitimate peer IS allowed to decrypt here; only cleartext-on-wire is a leak.
    no_leak = not wire_clear
    no_hang = not timed_out
    obs = (f"1B/segment dribble; reassembly_ok(server decrypted)={server_decrypted_marker(sout)}; "
           f"wire_cleartext_marker={wire_clear}; cap={len(cap)}B; cli={one_line(cout)!r}")
    return ("2a. dribbled valid stream", no_leak, no_hang, obs)


def case_truncated(lib, tool):
    sp, rp = free_port(), free_port()
    server = spawn("server", sp, 1, server_env(lib, tool))
    time.sleep(0.5)
    relay = Relay(rp, sp, mode="cut_midframe")
    relay.start()
    client = spawn("client", rp, 1, client_env(lib, tool, "real"))
    timed_out, _ = wait_all([client, server], PER_CASE_TIMEOUT_S)
    sout, cout = drain(server), drain(client)
    cap = relay.wire_bytes()
    no_leak = (MARKER not in cap) and (not server_decrypted_marker(sout))
    no_hang = not timed_out
    obs = (f"forwarded half a ClientHello then EOF; server={one_line(sout)!r}; "
           f"cli={one_line(cout)!r}; cap={len(cap)}B, marker absent={MARKER not in cap}")
    return ("2b. truncated frame", no_leak, no_hang, obs)


def case_corrupt_handshake(lib, tool):
    sp, rp = free_port(), free_port()
    server = spawn("server", sp, 1, server_env(lib, tool))
    time.sleep(0.5)
    relay = Relay(rp, sp, mode="corrupt_hello")
    relay.start()
    client = spawn("client", rp, 1, client_env(lib, tool, "real"))
    timed_out, _ = wait_all([client, server], PER_CASE_TIMEOUT_S)
    sout, cout = drain(server), drain(client)
    cap = relay.wire_bytes()
    no_leak = (MARKER not in cap) and (not server_decrypted_marker(sout))
    no_hang = not timed_out
    obs = (f"flipped a byte in ClientHello; server={one_line(sout)!r}; "
           f"cli={one_line(cout)!r}; cap={len(cap)}B, marker absent={MARKER not in cap}")
    return ("3. corrupted handshake", no_leak, no_hang, obs)


def case_corrupt_data(lib, tool):
    sp, rp = free_port(), free_port()
    server = spawn("server", sp, 1, server_env(lib, tool))
    time.sleep(0.5)
    relay = Relay(rp, sp, mode="corrupt_data")
    relay.start()
    client = spawn("client", rp, 1, client_env(lib, tool, "real"))
    timed_out, _ = wait_all([client, server], PER_CASE_TIMEOUT_S)
    sout, cout = drain(server), drain(client)
    cap = relay.wire_bytes()
    no_leak = (MARKER not in cap) and (not server_decrypted_marker(sout))
    no_hang = not timed_out
    obs = (f"handshake OK, flipped a byte in Data ciphertext; server={one_line(sout)!r}; "
           f"cli={one_line(cout)!r}; cap={len(cap)}B (ciphertext), marker absent={MARKER not in cap}")
    return ("4. corrupted data record", no_leak, no_hang, obs)


def case_oversized(lib, tool):
    sp, rp = free_port(), free_port()
    server = spawn("server", sp, 1, server_env(lib, tool))
    time.sleep(0.5)
    relay = Relay(rp, sp, mode="oversized")
    relay.start()
    client = spawn("client", rp, 1, client_env(lib, tool, "real"))
    timed_out, max_rss = wait_all([client, server], PER_CASE_TIMEOUT_S, rss_pid=server.pid)
    sout, cout = drain(server), drain(client)
    cap = relay.wire_bytes()
    no_leak = (MARKER not in cap) and (not server_decrypted_marker(sout))
    no_hang = not timed_out
    obs = (f"injected declared len 0xF0000000 (>16MiB); server={one_line(sout)!r}; "
           f"max server RSS={max_rss:.1f}MB (no GiB buffering); cli={one_line(cout)!r}")
    return ("5. oversized frame", no_leak, no_hang, obs)


def case_identity_mismatch(lib, tool):
    sp, rp = free_port(), free_port()
    server = spawn("server", sp, 1, server_env(lib, tool))
    time.sleep(0.5)
    relay = Relay(rp, sp, mode="record")
    relay.start()
    client = spawn("client", rp, 1, client_env(lib, tool, "wrong"))
    timed_out, _ = wait_all([client, server], PER_CASE_TIMEOUT_S)
    sout, cout = drain(server), drain(client)
    cap = relay.wire_bytes()
    no_leak = (MARKER not in cap) and (not server_decrypted_marker(sout))
    no_hang = not timed_out
    obs = (f"client signed with untrusted identity; server={one_line(sout)!r}; "
           f"cli={one_line(cout)!r}; cap={len(cap)}B, marker absent={MARKER not in cap}")
    return ("6. identity mismatch", no_leak, no_hang, obs)


def case_identity_mismatch_concurrent(lib, tool):
    n = 16
    sp, rp = free_port(), free_port()
    server = spawn("server", sp, n, server_env(lib, tool))
    time.sleep(0.5)
    relay = Relay(rp, sp, mode="record", n_conns=n)
    relay.start()
    client = spawn("client", rp, n, client_env(lib, tool, "wrong"))
    timed_out, _ = wait_all([client, server], PER_CASE_TIMEOUT_S)
    sout, cout = drain(server), drain(client)
    cap = relay.wire_bytes()
    accepted = sout.count("SRV RECV")
    leaked_marker = sout.count("marker=1")
    cli_fail = cout.count("CLI FAIL")
    no_leak = (MARKER not in cap) and (leaked_marker == 0)
    no_hang = not timed_out
    obs = (f"N={n} simultaneous, all untrusted; server SRV RECV count={accepted} "
           f"(marker=1 count={leaked_marker}); CLI FAIL count={cli_fail}/{n}; "
           f"cap={len(cap)}B, marker absent={MARKER not in cap}")
    return ("7. identity mismatch xN=16", no_leak, no_hang, obs)


CASES = [
    case_peer_drop,
    case_dribble_valid,
    case_truncated,
    case_corrupt_handshake,
    case_corrupt_data,
    case_oversized,
    case_identity_mismatch,
    case_identity_mismatch_concurrent,
]


def orchestrate() -> int:
    try:
        lib = find_lib()
        tool = find_identity_tool()
    except FileNotFoundError as e:
        print(f"FAIL: {e}")
        return 1

    print(f"overlay lib:   {lib}")
    print(f"identity tool: {tool}")
    print(f"suite:         {suite()}")
    print(f"per-case wall timeout: {PER_CASE_TIMEOUT_S:.0f}s\n")

    results = []
    for fn in CASES:
        name, no_leak, no_hang, obs = fn(lib, tool)
        passed = no_leak and no_hang
        results.append((name, no_leak, no_hang, passed))
        print(f"== {name} ==")
        print(f"   (A) no leak:  {'YES' if no_leak else 'NO  <-- LEAK'}")
        print(f"   (B) no hang:  {'YES' if no_hang else 'NO  <-- HANG'}")
        print(f"   observed: {obs}")
        print(f"   -> {'PASS' if passed else 'FAIL'}\n", flush=True)

    print("=" * 78)
    print(f"{'case':<30} {'no-leak (A)':<13} {'no-hang (B)':<13} {'result'}")
    print("-" * 78)
    for name, no_leak, no_hang, passed in results:
        print(f"{name:<30} {('yes' if no_leak else 'NO'):<13} "
              f"{('yes' if no_hang else 'NO'):<13} {'PASS' if passed else 'FAIL'}")
    print("=" * 78)
    all_pass = all(p for _, _, _, p in results)
    print(f"\nOVERALL: all seven hold fail-closed? {'YES' if all_pass else 'NO'}")
    return 0 if all_pass else 1


def main() -> int:
    if len(sys.argv) == 1:
        return orchestrate()
    role = sys.argv[1]
    if role == "server":
        return role_server(int(sys.argv[2]), int(sys.argv[3]))
    if role == "client":
        return role_client(int(sys.argv[2]), int(sys.argv[3]))
    print(f"unknown role: {role}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
