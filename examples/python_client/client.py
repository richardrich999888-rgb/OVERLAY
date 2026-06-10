#!/usr/bin/env python3
import socket
import sys


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: client.py HOST PORT", file=sys.stderr)
        return 2
    try:
        with socket.create_connection((sys.argv[1], int(sys.argv[2])), timeout=3):
            print("connect succeeds")
            return 0
    except OSError as exc:
        print(f"connect failed: {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
