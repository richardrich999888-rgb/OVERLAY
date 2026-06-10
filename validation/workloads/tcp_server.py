#!/usr/bin/env python3
import socket
import sys
import threading


def handle(conn, marker):
    with conn:
        data = conn.recv(4096)
        sys.stdout.write(data.decode(errors="replace") + "\n")
        sys.stdout.flush()
        if marker.encode() in data:
            conn.sendall(b"marker-observed")
        else:
            conn.sendall(b"ok")


def main() -> int:
    if len(sys.argv) < 4:
        print("usage: tcp_server.py HOST PORT MARKER", file=sys.stderr)
        return 2
    host = sys.argv[1]
    port = int(sys.argv[2])
    marker = sys.argv[3]
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((host, port))
        srv.listen(128)
        print(f"listening {host}:{port}", flush=True)
        while True:
            conn, _ = srv.accept()
            threading.Thread(target=handle, args=(conn, marker), daemon=True).start()


if __name__ == "__main__":
    raise SystemExit(main())
