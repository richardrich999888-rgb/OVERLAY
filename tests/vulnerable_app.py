#!/usr/bin/env python3
"""Legacy, overlay-unaware TCP app.

The application believes it speaks plaintext. With the overlay preloaded, the
*wire* bytes are encrypted while this code is unchanged.

Usage:
    vulnerable_app.py server <port>
    vulnerable_app.py client <port> <message>

The client connects, sends one message, then reads an echo and prints it.
The server accepts one connection, prints the received plaintext, echoes it.
"""
import socket
import sys
import os

SECRET_DEFAULT = "CONFIDENTIAL_MISSION_DATA_STREAM"


def run_server(port: int) -> int:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(1)
    print(f"[server] listening on 127.0.0.1:{port}", flush=True)
    conn, _ = srv.accept()
    data, _anc, _flags, _addr = conn.recvmsg(4096)
    text = data.decode("utf-8", errors="replace")
    print(f"[server] received plaintext: {text}", flush=True)
    os.writev(conn.fileno(), [b"ACK:", data])
    conn.close()
    srv.close()
    return 0


def run_client(port: int, message: str) -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("127.0.0.1", port))
    msg = message.encode("utf-8")
    mid = max(1, len(msg) // 2)
    s.sendmsg([msg[:mid], msg[mid:]])
    echo = os.read(s.fileno(), 4096)
    print(f"[client] received echo: {echo.decode('utf-8', errors='replace')}", flush=True)
    s.close()
    return 0


def main() -> int:
    if len(sys.argv) < 3:
        print(__doc__)
        return 2
    role, port = sys.argv[1], int(sys.argv[2])
    if role == "server":
        return run_server(port)
    if role == "client":
        msg = sys.argv[3] if len(sys.argv) > 3 else SECRET_DEFAULT
        return run_client(port, msg)
    print(f"unknown role: {role}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
