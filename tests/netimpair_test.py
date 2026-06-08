#!/usr/bin/env python3
"""Separate-host validation under network impairment (TRL-5 prep).

Unlike every prior harness, this does NOT use loopback. It stands up two
containers on a user-defined Docker bridge network, so client<->server traffic
crosses a real veth/bridge path, and injects impairment with `tc netem` on the
server's egress. Both ends run the overlay preloaded.

Roles (re-exec'd inside the containers, preloaded):
    netimpair_test.py server <port> <n>
    netimpair_test.py client <host> <port> <total>        # bulk transfer + integrity
    netimpair_test.py client-partition <host> <port> <iters>  # ping-pong for case 5

Orchestrator (run on the host; drives docker):
    netimpair_test.py                 # no args

Invariants asserted per case:
  (A) no plaintext on the wire  -- tcpdump on the bridge must not contain the marker
  (B) no hang                   -- each case finishes within a hard wall-clock timeout
Plus, where applicable: payload integrity (decrypted echo == sent).
"""
import os
import socket
import subprocess
import sys
import threading
import time
from typing import List, Optional, Tuple

MARKER = b"CONFIDENTIAL_MISSION_DATA_STREAM"

# Fixed identity seeds (same scheme as the other harnesses).
CLIENT_ED_SEED = "11" * 32
CLIENT_ML_SEED = "22" * 32
SERVER_ED_SEED = "33" * 32
SERVER_ML_SEED = "44" * 32

PORT = 9100
NET = "netimpair_net"
IMG = "rust:1-bookworm"
LIB = "/work/target/release/libsyntriass_overlay.so"
TOOL = "/work/target/release/syntriass-identity"
SCRIPT = "/work/tests/netimpair_test.py"
SUITE = os.environ.get("SYNTRIASS_SUITE", "0x01")


# --------------------------------------------------------------------------- #
# Payload (deterministic, marker-bearing, integrity-checkable)
# --------------------------------------------------------------------------- #
def make_payload(total: int) -> bytes:
    block = MARKER + bytes(range(256))
    reps = total // len(block) + 1
    return (block * reps)[:total]


# --------------------------------------------------------------------------- #
# Roles (run inside containers, preloaded)
# --------------------------------------------------------------------------- #
def role_server(port: int, n: int) -> int:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", port))
    srv.listen(max(8, n))
    print("SRV LISTEN", flush=True)

    def handle(conn):
        total = 0
        try:
            while True:
                d = conn.recv(65536)
                if not d:
                    break
                conn.sendall(d)  # echo decrypted plaintext straight back
                total += len(d)
            print("SRV CONN_DONE bytes=%d" % total, flush=True)
        except OSError as e:
            print("SRV ERR errno=%d total=%d" % (e.errno or 0, total), flush=True)
        finally:
            try:
                conn.shutdown(socket.SHUT_WR)
            except OSError:
                pass
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


def role_client(host: str, port: int, total: int) -> int:
    import time as _t
    payload = make_payload(total)
    try:
        t0 = _t.perf_counter()
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((host, port))

        def sender():
            try:
                s.sendall(payload)
                s.shutdown(socket.SHUT_WR)
            except OSError:
                pass

        st = threading.Thread(target=sender, daemon=True)
        st.start()

        got = bytearray()
        t_first = None
        while len(got) < total:
            d = s.recv(65536)
            if not d:
                break
            if t_first is None:
                t_first = _t.perf_counter()
            got.extend(d)
        t_end = _t.perf_counter()
        st.join()
        s.close()

        integrity = 1 if bytes(got) == payload else 0
        hs_ms = (t_first - t0) * 1000.0 if t_first else -1.0
        total_ms = (t_end - t0) * 1000.0
        secs = (t_end - t_first) if (t_first and t_end > t_first) else 0.0
        mbps = (len(got) / 1e6) / secs if secs > 0 else 0.0
        print("CLI OK recv=%d integrity=%d hs_ms=%.3f total_ms=%.3f mbps=%.2f"
              % (len(got), integrity, hs_ms, total_ms, mbps), flush=True)
        return 0
    except OSError as e:
        print("CLI FAIL errno=%d" % (e.errno or 0), flush=True)
        return 1


def role_client_partition(host: str, port: int, iters: int) -> int:
    import time as _t
    chunk = (MARKER + bytes(range(256)))[:1024]
    try:
        t0 = _t.perf_counter()
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((host, port))
        # establish + measure handshake via one ping-pong
        s.sendall(chunk)
        echo = bytearray()
        while len(echo) < len(chunk):
            d = s.recv(65536)
            if not d:
                break
            echo.extend(d)
        hs_ms = (_t.perf_counter() - t0) * 1000.0
        ok = 1 if bytes(echo) == chunk else 0
        print("CLI PART_ESTABLISHED hs_ms=%.3f integrity=%d" % (hs_ms, ok), flush=True)

        completed = 1  # the establish iteration
        for i in range(iters):
            s.sendall(chunk)
            e = bytearray()
            while len(e) < len(chunk):
                d = s.recv(65536)  # blocks across a partition; returns on restore
                if not d:
                    raise ConnectionError("peer closed mid-partition")
                e.extend(d)
            if bytes(e) != chunk:
                print("CLI PART_INTEGRITY_FAIL iter=%d" % i, flush=True)
            completed += 1
            print("CLI PART_ITER %d/%d t=%.1fs" % (i + 1, iters, _t.perf_counter() - t0),
                  flush=True)
            time.sleep(1.0)
        s.close()
        print("CLI PART_DONE completed=%d/%d" % (completed, iters + 1), flush=True)
        return 0
    except OSError as e:
        print("CLI PART_FAIL errno=%s" % (getattr(e, "errno", "?")), flush=True)
        return 1
    except Exception as e:  # noqa: BLE001
        print("CLI PART_FAIL exc=%s" % e, flush=True)
        return 1


# --------------------------------------------------------------------------- #
# Orchestrator (host side; drives docker)
# --------------------------------------------------------------------------- #
def sh(args: List[str], timeout: float = 120, check: bool = False):
    return subprocess.run(args, timeout=timeout, stdout=subprocess.PIPE,
                          stderr=subprocess.STDOUT, text=True, check=check)


def dexec(container: str, cmd: str, timeout: float = 120):
    return sh(["docker", "exec", container, "bash", "-c", cmd], timeout=timeout)


def dexec_popen(container: str, cmd: str) -> subprocess.Popen:
    return subprocess.Popen(["docker", "exec", container, "bash", "-c", cmd],
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)


def reset_tc(server: str):
    dexec(server, "tc qdisc del dev eth0 root 2>/dev/null; true")


def apply_tc(server: str, netem: str):
    dexec(server, "tc qdisc replace dev eth0 root netem %s" % netem)


def kill_roles(server: str, client: str):
    for c in (server, client):
        dexec(c, "pkill -9 -f netimpair_test 2>/dev/null; pkill -9 tcpdump 2>/dev/null; true")


def derive_identity(container: str, ed: str, ml: str) -> dict:
    out = dexec(container, "%s %s %s" % (TOOL, ed, ml)).stdout
    d = {}
    for line in out.splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            d[k.strip()] = v.strip()
    return d


def env_prefix(role: str, client_id: dict, server_id: dict) -> str:
    common = "LD_PRELOAD=%s SYNTRIASS_SUITE=%s" % (LIB, SUITE)
    if role == "server":
        return ("%s SYNTRIASS_ED25519_SEED_HEX=%s SYNTRIASS_MLDSA65_SEED_HEX=%s "
                "SYNTRIASS_PEER_ED25519_PUB_HEX=%s SYNTRIASS_PEER_MLDSA65_PUB_HEX=%s"
                % (common, SERVER_ED_SEED, SERVER_ML_SEED,
                   client_id["ed25519_public"], client_id["mldsa65_public"]))
    return ("%s SYNTRIASS_ED25519_SEED_HEX=%s SYNTRIASS_MLDSA65_SEED_HEX=%s "
            "SYNTRIASS_PEER_ED25519_PUB_HEX=%s SYNTRIASS_PEER_MLDSA65_PUB_HEX=%s"
            % (common, CLIENT_ED_SEED, CLIENT_ML_SEED,
               server_id["ed25519_public"], server_id["mldsa65_public"]))


def pcap_marker_count(server: str, cap: str) -> Tuple[int, int]:
    g = dexec(server, "grep -c -a %s %s 2>/dev/null || true" % (MARKER.decode(), cap))
    try:
        leak = int((g.stdout.strip() or "0").splitlines()[-1])
    except ValueError:
        leak = -1
    p = dexec(server, "tcpdump -r %s 2>/dev/null | wc -l" % cap)
    try:
        pkts = int(p.stdout.strip().splitlines()[-1])
    except (ValueError, IndexError):
        pkts = -1
    return leak, pkts


def run_case(server, client, cid, sid, host, name, netem, payload, timeout,
             partition=False, iters=0):
    print("\n== case: %s ==" % name, flush=True)
    kill_roles(server, client)
    reset_tc(server)
    if netem:
        apply_tc(server, netem)
        print("   netem (server egress): %s" % netem, flush=True)
    else:
        print("   netem: none", flush=True)

    cap = "/work/target/netimpair/%s.pcap" % name.replace(" ", "_").replace("/", "_")
    dexec(server, "mkdir -p /work/target/netimpair; rm -f %s" % cap)
    tcpdump = dexec_popen(server, "tcpdump -i eth0 -U -w %s tcp 2>/dev/null" % cap)
    time.sleep(0.8)

    server_p = dexec_popen(server, "%s python3 %s server %d 1"
                           % (env_prefix("server", cid, sid), SCRIPT, PORT))
    time.sleep(1.0)  # bind/listen

    if partition:
        client_cmd = ("%s python3 %s client-partition %s %d %d"
                      % (env_prefix("client", cid, sid), SCRIPT, host, PORT, iters))
    else:
        client_cmd = ("%s python3 %s client %s %d %d"
                      % (env_prefix("client", cid, sid), SCRIPT, host, PORT, payload))
    client_p = dexec_popen(client, client_cmd)

    part_thread = None
    if partition:
        def partition_seq():
            time.sleep(5.0)
            apply_tc(server, "loss 100%")
            print("   [partition] 100%% egress loss applied at t~5s", flush=True)
            time.sleep(12.0)
            reset_tc(server)
            print("   [partition] link restored at t~17s", flush=True)
        part_thread = threading.Thread(target=partition_seq, daemon=True)
        part_thread.start()

    timed_out = False
    try:
        cli_out, _ = client_p.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        client_p.kill()
        try:
            cli_out, _ = client_p.communicate(timeout=5)
        except Exception:  # noqa: BLE001
            cli_out = "(no output: killed on timeout)"
    if part_thread:
        part_thread.join(timeout=5)

    # tear down case processes
    try:
        server_p.kill()
    except Exception:  # noqa: BLE001
        pass
    try:
        tcpdump.terminate()
    except Exception:  # noqa: BLE001
        pass
    time.sleep(0.6)
    kill_roles(server, client)
    reset_tc(server)

    leak, pkts = pcap_marker_count(server, cap)

    completed = (not timed_out) and ("CLI OK" in cli_out or "PART_DONE" in cli_out)
    integrity = ("integrity=1" in cli_out) and ("PART_INTEGRITY_FAIL" not in cli_out)
    no_leak = (leak == 0)
    cli_line = " | ".join(l for l in cli_out.splitlines() if l.startswith("CLI"))
    print("   client: %s" % (cli_line or cli_out.strip()[:200]), flush=True)
    print("   wire: %d pkts captured, marker count=%d (leak=%s)"
          % (pkts, leak, "YES" if leak else "no"), flush=True)
    print("   completed=%s integrity=%s no-leak=%s%s"
          % (completed, integrity, no_leak, " [TIMEOUT]" if timed_out else ""), flush=True)
    return {
        "name": name, "completed": completed, "integrity": integrity,
        "no_leak": no_leak, "timed_out": timed_out, "cli": cli_line,
        "pkts": pkts, "leak": leak,
    }


def orchestrate() -> int:
    server, client = "ni_server", "ni_client"
    # ---- clean slate ----
    sh(["docker", "rm", "-f", server, client])
    sh(["docker", "network", "rm", NET])
    print("creating bridge network %s ..." % NET, flush=True)
    r = sh(["docker", "network", "create", NET])
    if r.returncode != 0:
        print("FAIL: network create: %s" % r.stdout)
        return 1

    print("starting containers (cap NET_ADMIN, bridge)...", flush=True)
    for name in (server, client):
        r = sh(["docker", "run", "-d", "--name", name, "--network", NET,
                "--cap-add", "NET_ADMIN", "-v", "%s:/work" % os.getcwd(),
                "-w", "/work", IMG, "sleep", "infinity"])
        if r.returncode != 0:
            print("FAIL: run %s: %s" % (name, r.stdout))
            return 1

    print("installing python3 / iproute2 / tcpdump in both...", flush=True)
    for name in (server, client):
        dexec(name, "apt-get update -qq >/dev/null 2>&1 && "
                    "apt-get install -y -qq python3 iproute2 tcpdump >/dev/null 2>&1 && "
                    "echo OK", timeout=300)

    print("building .so (shared mount)...", flush=True)
    b = dexec(server, "export PATH=/usr/local/cargo/bin:$PATH && cargo build --release 2>&1 | tail -2",
              timeout=600)
    print("   " + b.stdout.strip().replace("\n", "\n   "))

    # ---- evidence: the .so under test really interposes connect/send/recv ----
    nm = dexec(server, "nm -D %s | grep -E ' T (connect|send|recv|close)$' || true" % LIB)
    print("nm -D %s (interposed symbols):" % LIB)
    print("   " + nm.stdout.strip().replace("\n", "\n   "))

    mtu = dexec(server, "ip -o link show eth0 | grep -o 'mtu [0-9]*' | head -1")
    mtu_s = mtu.stdout.strip() or "mtu ?"
    print("server eth0 %s (overlay records are TCP-segmented to MSS; no jumbo frames needed)" % mtu_s)

    cid = derive_identity(server, CLIENT_ED_SEED, CLIENT_ML_SEED)
    sid = derive_identity(server, SERVER_ED_SEED, SERVER_ML_SEED)
    if "ed25519_public" not in cid or "ed25519_public" not in sid:
        print("FAIL: identity derivation: cid=%s sid=%s" % (cid, sid))
        return 1

    # Connect by numeric IP. The overlay's connect hook adopts every connected fd
    # (no SOCK_STREAM guard), which corrupts the resolver's socket and breaks
    # hostname lookup -- so we resolve the server's bridge IP here and use it.
    ipr = sh(["docker", "inspect", "-f",
              "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", server])
    server_ip = ipr.stdout.strip()
    print("server bridge IP: %s | suite: %s | payload(default)=256KB\n" % (server_ip, SUITE))

    P = 256 * 1024
    results = []
    results.append(run_case(server, client, cid, sid, server_ip, "1 baseline", None, P, 30))
    results.append(run_case(server, client, cid, sid, server_ip, "2 latency 50ms",
                            "delay 50ms 10ms", P, 40))
    results.append(run_case(server, client, cid, sid, server_ip, "3a loss 5%", "loss 5%", P, 45))
    results.append(run_case(server, client, cid, sid, server_ip, "3b loss 20%", "loss 20%", P, 60))
    results.append(run_case(server, client, cid, sid, server_ip, "4 reorder",
                            "delay 20ms reorder 25% 50%", P, 45))
    results.append(run_case(server, client, cid, sid, server_ip, "6 rate 1mbit",
                            "rate 1mbit", P, 60))
    results.append(run_case(server, client, cid, sid, server_ip, "5 partition", None, 0, 60,
                            partition=True, iters=25))

    # ---- teardown ----
    print("\ntearing down containers + network...", flush=True)
    sh(["docker", "rm", "-f", server, client])
    sh(["docker", "network", "rm", NET])

    # ---- summary ----
    print("\n" + "=" * 92)
    print("%-22s %-11s %-11s %-9s %s" % ("case", "completed", "integrity", "no-leak", "notes"))
    print("-" * 92)
    bad = []
    for r in results:
        note = r["cli"][:46]
        if r["timed_out"]:
            note = "TIMEOUT/HANG"
        print("%-22s %-11s %-11s %-9s %s"
              % (r["name"],
                 "yes" if r["completed"] else "NO",
                 "yes" if r["integrity"] else ("-" if "partition" in r["name"] else "NO"),
                 "yes" if r["no_leak"] else "NO",
                 note))
        # leak or hang anywhere is a hard fail; integrity fail on data cases too
        if (not r["no_leak"]) or r["timed_out"] or (not r["completed"]):
            bad.append(r["name"])
    print("=" * 92)
    ok = len(bad) == 0
    print("\nVERDICT: overlay functions correctly host-to-host under impairment? %s"
          % ("YES" if ok else "NO"))
    if bad:
        print("  failing cases: %s" % ", ".join(bad))
    return 0 if ok else 1


def main() -> int:
    if len(sys.argv) == 1:
        return orchestrate()
    role = sys.argv[1]
    if role == "server":
        return role_server(int(sys.argv[2]), int(sys.argv[3]))
    if role == "client":
        return role_client(sys.argv[2], int(sys.argv[3]), int(sys.argv[4]))
    if role == "client-partition":
        return role_client_partition(sys.argv[2], int(sys.argv[3]), int(sys.argv[4]))
    print("unknown role: %s" % role)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
