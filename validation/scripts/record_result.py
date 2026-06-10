#!/usr/bin/env python3
import json
import sys
from pathlib import Path


def main() -> int:
    matrix, scenario, workload, expected, exit_code, audit_count, plaintext, pcap, stdout, stderr = sys.argv[1:]
    exit_code_i = int(exit_code)
    audit_count_i = int(audit_count)
    plaintext_b = plaintext.lower() == "true"
    observed = "success" if exit_code_i == 0 else "blocked"
    record = {
        "scenario": scenario,
        "workload": workload,
        "expected": expected,
        "observed": observed,
        "exit_code": exit_code_i,
        "audit_count": audit_count_i,
        "audit_present": audit_count_i > 0,
        "plaintext_marker_observed": plaintext_b,
        "pcap": pcap,
        "stdout": Path(stdout).read_text(errors="ignore"),
        "stderr": Path(stderr).read_text(errors="ignore"),
    }
    record["pass"] = (record["expected"] == record["observed"]) and record["audit_present"]
    if record["observed"] == "success":
        record["pass"] = record["pass"] and not record["plaintext_marker_observed"]
    with open(matrix, "a", encoding="utf-8") as f:
        f.write(json.dumps(record, sort_keys=True) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
