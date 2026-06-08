#!/usr/bin/env python3
"""Performance characterization for the Syntriass overlay (measurement only).

No assertions, no pass/fail -- just measured numbers, each overlay figure placed
next to a plain-TCP baseline so the cost of the tunnel is visible and the numbers
are sanity-checkable (e.g. 0x02 handshake must cost more than 0x01; overlay
throughput must be a fraction of plain TCP, not equal to it).

Both ends run preloaded (LD_PRELOAD) for the overlay configs; for the baseline
the same role code runs over plain TCP with no preload. Roles are re-exec'd from
this same file, exactly like concurrency_test.py / failclosed_test.py.

    characterize.py serve-echo <port> <count>          # sequential 1-byte echo server
    characterize.py serve-echo-concurrent <port> <n>   # threaded 1-byte echo server
    characterize.py recv-sink <port> <total>           # drain <total> bytes, time it (c2s)
    characterize.py send-source <port> <total>         # send <total> bytes (s2c)
    characterize.py client-handshakes <port> <count>   # sequential connect+rtt, print per-sample ms
    characterize.py client-send <port> <total>         # send <total> bytes (c2s sender)
    characterize.py client-recv <port> <total>         # drain <total> bytes, time it (s2c)
    characterize.py client-setup <port> <n>            # N concurrent handshakes, print setup metrics
    characterize.py                                     # orchestrator (no preload)

Measures, for suites 0x01, 0x02, and plain-TCP baseline:
  1. Handshake latency (connect -> first app byte), >=100 sequential, median/p95/max.
  2. Sustained throughput over one connection, ~100 MB, c2s and s2c separately.
  3. Connection setup rate under N=64 concurrent (the concurrency_test load shape).
  4. Plain-TCP baseline beside every overlay number.
"""
import os
import socket
import statistics
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Optional

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
SELF = str(Path(__file__).resolve())
HOST = "127.0.0.1"

# Parameters
HS_SAMPLES = 100          # sequential handshakes per run
HS_RUNS = 3               # repeat the whole 100-sample run this many times
TP_TOTAL = 100_000_000    # ~100 MB (decimal) per throughput transfer
TP_RUNS = 3
SETUP_N = 64              # concurrent connections (concurrency_test shape)
SETUP_RUNS = 3
SEND_CHUNK = 256 * 1024   # sender userspace chunk; overlay re-chunks to 64 KiB records

CLIENT_ED_SEED = "11" * 32
CLIENT_ML_SEED = "22" * 32
SERVER_ED_SEED = "33" * 32
SERVER_ML_SEED = "44" * 32


# --------------------------------------------------------------------------- #
# Role helpers
# --------------------------------------------------------------------------- #
def recv_exact_count(sock: socket.socket, total: int):
    """Drain exactly `total` bytes. Returns (first_byte_perf, last_byte_perf)."""
    got = 0
    t_first = None
    while got < total:
        chunk = sock.recv(1 << 20)
        if not chunk:
            break
        if t_first is None:
            t_first = time.perf_counter()
        got += len(chunk)
    t_last = time.perf_counter()
    return t_first, t_last, got


def send_total(sock: socket.socket, total: int):
    buf = b"\xab" * SEND_CHUNK
    sent = 0
    while sent < total:
        n = min(SEND_CHUNK, total - sent)
        sock.sendall(buf[:n])
        sent += n
    return sent


# --------------------------------------------------------------------------- #
# Server roles
# --------------------------------------------------------------------------- #
def role_serve_echo(port: int, count: int) -> int:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((HOST, port))
    srv.listen(128)
    print(f"READY {port}", flush=True)
    for _ in range(count):
        try:
            conn, _ = srv.accept()
        except OSError:
            break
        try:
            data = conn.recv(64)
            if data:
                conn.sendall(data[:1])
        except OSError:
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass
    srv.close()
    return 0


def role_serve_echo_concurrent(port: int, n: int) -> int:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((HOST, port))
    srv.listen(max(128, n))
    print(f"READY {port}", flush=True)

    def handle(conn):
        try:
            data = conn.recv(64)
            if data:
                conn.sendall(data[:1])
        except OSError:
            pass
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
    srv.close()
    return 0


def role_recv_sink(port: int, total: int) -> int:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((HOST, port))
    srv.listen(1)
    print(f"READY {port}", flush=True)
    conn, _ = srv.accept()
    t_first, t_last, got = recv_exact_count(conn, total)
    try:
        conn.sendall(b"D")  # signal sender we are done
    except OSError:
        pass
    conn.close()
    srv.close()
    if t_first and got >= total:
        secs = t_last - t_first
        mbps = (got / 1e6) / secs if secs > 0 else 0.0
        print(f"C2S_MBPS={mbps:.2f} bytes={got} secs={secs:.4f}", flush=True)
    else:
        print(f"C2S_MBPS=0 bytes={got}", flush=True)
    return 0


def role_send_source(port: int, total: int) -> int:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((HOST, port))
    srv.listen(1)
    print(f"READY {port}", flush=True)
    conn, _ = srv.accept()
    try:
        send_total(conn, total)
        conn.shutdown(socket.SHUT_WR)
        conn.recv(16)  # wait for receiver ack so we don't close early
    except OSError:
        pass
    conn.close()
    srv.close()
    return 0


# --------------------------------------------------------------------------- #
# Client roles
# --------------------------------------------------------------------------- #
def role_client_handshakes(port: int, count: int) -> int:
    samples = []
    for _ in range(count):
        try:
            t0 = time.perf_counter()
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((HOST, port))
            s.sendall(b"X")
            r = s.recv(16)
            t1 = time.perf_counter()
            s.close()
            if r:
                samples.append((t1 - t0) * 1000.0)
        except OSError:
            pass
    print("HS_SAMPLES=" + ",".join(f"{x:.4f}" for x in samples), flush=True)
    return 0


def role_client_send(port: int, total: int) -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((HOST, port))
    try:
        send_total(s, total)
        s.shutdown(socket.SHUT_WR)
        s.recv(16)  # wait for sink's done-signal
    except OSError:
        pass
    s.close()
    return 0


def role_client_recv(port: int, total: int) -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((HOST, port))
    # Prod the server to start sending (handshake is initiated by the client).
    try:
        s.sendall(b"G")
    except OSError:
        pass
    t_first, t_last, got = recv_exact_count(s, total)
    try:
        s.sendall(b"D")
    except OSError:
        pass
    s.close()
    if t_first and got >= total:
        secs = t_last - t_first
        mbps = (got / 1e6) / secs if secs > 0 else 0.0
        print(f"S2C_MBPS={mbps:.2f} bytes={got} secs={secs:.4f}", flush=True)
    else:
        print(f"S2C_MBPS=0 bytes={got}", flush=True)
    return 0


def role_client_setup(port: int, n: int) -> int:
    barrier = threading.Barrier(n)
    per_conn = [None] * n

    def worker(i):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((HOST, port))
            barrier.wait()  # release all together -> peak setup contention
            t0 = time.perf_counter()
            s.sendall(b"X")
            r = s.recv(16)
            t1 = time.perf_counter()
            s.close()
            if r:
                per_conn[i] = (t0, t1)
        except OSError:
            pass

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    done = [v for v in per_conn if v is not None]
    if not done:
        print("SETUP hps=0 p95_ms=0 wall_ms=0 completed=0", flush=True)
        return 0
    t_start = min(t0 for t0, _ in done)
    t_end = max(t1 for _, t1 in done)
    wall = t_end - t_start
    durations = sorted((t1 - t0) * 1000.0 for t0, t1 in done)
    p95 = durations[min(len(durations) - 1, int(0.95 * len(durations)))]
    hps = len(done) / wall if wall > 0 else 0.0
    print(f"SETUP hps={hps:.2f} p95_ms={p95:.4f} wall_ms={wall * 1000:.4f} "
          f"completed={len(done)}", flush=True)
    return 0


ROLE_TABLE = {
    "serve-echo": role_serve_echo,
    "serve-echo-concurrent": role_serve_echo_concurrent,
    "recv-sink": role_recv_sink,
    "send-source": role_send_source,
    "client-handshakes": role_client_handshakes,
    "client-send": role_client_send,
    "client-recv": role_client_recv,
    "client-setup": role_client_setup,
}
SERVER_ROLES = {"serve-echo", "serve-echo-concurrent", "recv-sink", "send-source"}


# --------------------------------------------------------------------------- #
# Orchestrator
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


def make_env(role: str, suite: Optional[str], lib: str, tool: str) -> dict:
    """suite=None -> plain TCP (no preload). Otherwise overlay with that suite."""
    env = dict(os.environ)
    if suite is None:
        env.pop("LD_PRELOAD", None)
        return env
    env["LD_PRELOAD"] = lib
    client = derive_identity(tool, CLIENT_ED_SEED, CLIENT_ML_SEED)
    server = derive_identity(tool, SERVER_ED_SEED, SERVER_ML_SEED)
    if role in SERVER_ROLES:
        env.update({
            "SYNTRIASS_SUITE": suite,
            "SYNTRIASS_ED25519_SEED_HEX": SERVER_ED_SEED,
            "SYNTRIASS_MLDSA65_SEED_HEX": SERVER_ML_SEED,
            "SYNTRIASS_PEER_ED25519_PUB_HEX": client["ed25519_public"],
            "SYNTRIASS_PEER_MLDSA65_PUB_HEX": client["mldsa65_public"],
        })
    else:
        env.update({
            "SYNTRIASS_SUITE": suite,
            "SYNTRIASS_ED25519_SEED_HEX": CLIENT_ED_SEED,
            "SYNTRIASS_MLDSA65_SEED_HEX": CLIENT_ML_SEED,
            "SYNTRIASS_PEER_ED25519_PUB_HEX": server["ed25519_public"],
            "SYNTRIASS_PEER_MLDSA65_PUB_HEX": server["mldsa65_public"],
        })
    return env


def free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((HOST, 0))
    port = s.getsockname()[1]
    s.close()
    return port


def spawn(role: str, port: int, arg: int, suite, lib, tool) -> subprocess.Popen:
    return subprocess.Popen(
        [sys.executable, SELF, role, str(port), str(arg)],
        env=make_env(role, suite, lib, tool),
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    )


def wait_ready(p: subprocess.Popen, timeout=10.0):
    """Block until the server prints its READY line (or dies/timeout)."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        line = p.stdout.readline()
        if not line:
            if p.poll() is not None:
                return False
            continue
        if line.startswith("READY"):
            return True
    return False


def grep(out: str, prefix: str) -> Optional[str]:
    for line in out.splitlines():
        if line.startswith(prefix):
            return line
    return None


def run_pair(server_role, client_role, arg, suite, lib, tool, timeout=90.0):
    """Spawn server+client, return (server_out, client_out)."""
    port = free_port()
    server = spawn(server_role, port, arg, suite, lib, tool)
    if not wait_ready(server):
        server.kill()
        return "", ""
    client = spawn(client_role, port, arg, suite, lib, tool)
    try:
        client.wait(timeout=timeout)
        server.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        client.kill(); server.kill()
    # server already had its READY line consumed; read the rest
    srv_rest = server.stdout.read() if server.stdout else ""
    cli_out = client.stdout.read() if client.stdout else ""
    return srv_rest, cli_out


def pct(values, q):
    s = sorted(values)
    return s[min(len(s) - 1, int(q * len(s)))]


def measure_handshakes(suite, lib, tool):
    all_samples = []
    run_medians = []
    for _ in range(HS_RUNS):
        _srv, cli = run_pair("serve-echo", "client-handshakes", HS_SAMPLES, suite, lib, tool)
        line = grep(cli, "HS_SAMPLES=")
        if not line:
            continue
        raw = line.split("=", 1)[1]
        samples = [float(x) for x in raw.split(",") if x]
        if samples:
            all_samples.extend(samples)
            run_medians.append(statistics.median(samples))
    if not all_samples:
        return None
    return {
        "n": len(all_samples),
        "median": statistics.median(all_samples),
        "p95": pct(all_samples, 0.95),
        "max": max(all_samples),
        "run_medians": run_medians,
    }


def measure_throughput(suite, lib, tool):
    c2s, s2c = [], []
    for _ in range(TP_RUNS):
        srv, _cli = run_pair("recv-sink", "client-send", TP_TOTAL, suite, lib, tool)
        line = grep(srv, "C2S_MBPS=")
        if line:
            c2s.append(float(line.split("=", 1)[1].split()[0]))
    for _ in range(TP_RUNS):
        _srv, cli = run_pair("send-source", "client-recv", TP_TOTAL, suite, lib, tool)
        line = grep(cli, "S2C_MBPS=")
        if line:
            s2c.append(float(line.split("=", 1)[1].split()[0]))
    return {"c2s": c2s, "s2c": s2c}


def measure_setup(suite, lib, tool):
    hps_list, p95_list = [], []
    for _ in range(SETUP_RUNS):
        _srv, cli = run_pair("serve-echo-concurrent", "client-setup", SETUP_N, suite, lib, tool, timeout=60)
        line = grep(cli, "SETUP ")
        if not line:
            continue
        fields = dict(tok.split("=") for tok in line.replace("SETUP ", "").split())
        hps_list.append(float(fields["hps"]))
        p95_list.append(float(fields["p95_ms"]))
    return {"hps": hps_list, "p95_ms": p95_list}


def spread(values):
    if not values:
        return "n/a"
    if len(values) == 1:
        return f"{values[0]:.2f}"
    return f"{min(values):.2f}..{max(values):.2f} (mean {statistics.mean(values):.2f})"


def core_count() -> str:
    py = os.cpu_count()
    try:
        nproc = subprocess.check_output(["nproc"], text=True).strip()
    except Exception:  # noqa: BLE001
        nproc = "?"
    return f"os.cpu_count()={py}, nproc={nproc}"


def orchestrate() -> int:
    try:
        lib = find_lib()
        tool = find_identity_tool()
    except FileNotFoundError as e:
        print(f"FAIL: {e}")
        return 1

    cores = core_count()
    print(f"container cores: {cores}")
    print(f"handshake: {HS_SAMPLES} sequential x {HS_RUNS} runs | "
          f"throughput: {TP_TOTAL/1e6:.0f} MB x {TP_RUNS} runs/dir | "
          f"setup: N={SETUP_N} x {SETUP_RUNS} runs\n")

    configs = [("0x01", "0x01"), ("0x02", "0x02"), ("plain", None)]
    data = {}
    for label, suite in configs:
        print(f"-- measuring config: {label} --", flush=True)
        hs = measure_handshakes(suite, lib, tool)
        tp = measure_throughput(suite, lib, tool)
        st = measure_setup(suite, lib, tool)
        data[label] = {"hs": hs, "tp": tp, "st": st}
        if hs:
            print(f"   handshake ms: median={hs['median']:.3f} p95={hs['p95']:.3f} "
                  f"max={hs['max']:.3f} (n={hs['n']}, run-medians="
                  f"{[round(x,3) for x in hs['run_medians']]})")
        print(f"   throughput MB/s c2s={spread(tp['c2s'])}  s2c={spread(tp['s2c'])}")
        print(f"   setup hps={spread(st['hps'])}  p95_ms={spread(st['p95_ms'])}\n", flush=True)

    # ---- summary table ----
    def cell(label, key):
        d = data[label]
        if key == "hs_med":
            return f"{d['hs']['median']:.2f}" if d["hs"] else "n/a"
        if key == "hs_p95":
            return f"{d['hs']['p95']:.2f}" if d["hs"] else "n/a"
        if key == "hs_max":
            return f"{d['hs']['max']:.2f}" if d["hs"] else "n/a"
        if key == "c2s":
            v = d["tp"]["c2s"]
            return f"{statistics.mean(v):.1f}" if v else "n/a"
        if key == "s2c":
            v = d["tp"]["s2c"]
            return f"{statistics.mean(v):.1f}" if v else "n/a"
        if key == "hps":
            v = d["st"]["hps"]
            return f"{statistics.mean(v):.1f}" if v else "n/a"
        if key == "setup_p95":
            v = d["st"]["p95_ms"]
            return f"{statistics.mean(v):.2f}" if v else "n/a"
        return "?"

    rows = [
        ("handshake latency median (ms)", "hs_med"),
        ("handshake latency p95 (ms)", "hs_p95"),
        ("handshake latency max (ms)", "hs_max"),
        ("throughput c2s (MB/s)", "c2s"),
        ("throughput s2c (MB/s)", "s2c"),
        ("setup rate (handshakes/s)", "hps"),
        ("setup p95 per-conn (ms)", "setup_p95"),
    ]
    print("=" * 86)
    print(f"{'metric':<34} {'suite 0x01':<16} {'suite 0x02':<16} {'plain-TCP':<16}")
    print("-" * 86)
    for name, key in rows:
        print(f"{name:<34} {cell('0x01', key):<16} {cell('0x02', key):<16} {cell('plain', key):<16}")
    print("=" * 86)

    # ---- relative cost vs baseline ----
    print("\nrelative to plain-TCP baseline:")
    if data["0x01"]["hs"] and data["plain"]["hs"]:
        base = data["plain"]["hs"]["median"]
        for s in ("0x01", "0x02"):
            m = data[s]["hs"]["median"]
            print(f"  handshake {s}: {m:.2f} ms vs {base:.2f} ms plain "
                  f"(+{m - base:.2f} ms over plain connect)")
    for direction, key in (("c2s", "c2s"), ("s2c", "s2c")):
        bv = data["plain"]["tp"][key]
        if not bv:
            continue
        base = statistics.mean(bv)
        for s in ("0x01", "0x02"):
            v = data[s]["tp"][key]
            if v:
                mv = statistics.mean(v)
                print(f"  throughput {direction} {s}: {mv:.1f} MB/s vs {base:.1f} MB/s plain "
                      f"= {100 * mv / base:.1f}% of baseline")

    print(f"\nsample counts: handshake n={HS_SAMPLES}x{HS_RUNS} per config; "
          f"throughput n={TP_RUNS} per direction; setup n={SETUP_RUNS} (N={SETUP_N} each)")
    print(f"container cores: {cores}")
    return 0


def main() -> int:
    if len(sys.argv) == 1:
        return orchestrate()
    role = sys.argv[1]
    fn = ROLE_TABLE.get(role)
    if not fn:
        print(f"unknown role: {role}")
        return 2
    return fn(int(sys.argv[2]), int(sys.argv[3]))


if __name__ == "__main__":
    raise SystemExit(main())
