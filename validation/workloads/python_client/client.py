#!/usr/bin/env python3
import socket
import sys


def main() -> int:
    if len(sys.argv) < 4:
        print("usage: client.py HOST PORT PAYLOAD", file=sys.stderr)
        return 2
    host = sys.argv[1]
    port = int(sys.argv[2])
    payload = sys.argv[3].encode()
    try:
        with socket.create_connection((host, port), timeout=3) as sock:
            sock.sendall(payload)
            print("connect succeeds")
            return 0
    except OSError as exc:
        print(f"connect failed: {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
