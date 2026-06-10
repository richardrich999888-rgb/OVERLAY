#!/usr/bin/env python3
import json
import sys
from pathlib import Path


def load_records(path: Path):
    matrix = path / "matrix.jsonl"
    if not matrix.exists():
        return []
    return [json.loads(line) for line in matrix.read_text().splitlines() if line.strip()]


def write(path: Path, name: str, body: str):
    report = path / "report"
    report.mkdir(parents=True, exist_ok=True)
    (report / name).write_text(body, encoding="utf-8")


def table(records):
    lines = ["| Scenario | Workload | Expected | Observed | Audit | Plaintext | Result |", "|---|---|---|---|---:|---|---|"]
    for r in records:
        lines.append(
            f"| {r['scenario']} | {r['workload']} | {r['expected']} | {r['observed']} | "
            f"{r['audit_count']} | {r['plaintext_marker_observed']} | {'PASS' if r['pass'] else 'FAIL'} |"
        )
    return "\n".join(lines)


def classification(records):
    if not records:
        return "A. Policy enforcement prototype"
    all_pass = all(r["pass"] for r in records)
    any_success = any(r["observed"] == "success" for r in records)
    no_plaintext_success = all(not r["plaintext_marker_observed"] for r in records if r["observed"] == "success")
    if all_pass and any_success and no_plaintext_success:
        return "B. PQC migration prototype"
    if any(r["observed"] == "blocked" for r in records):
        return "A. Policy enforcement prototype"
    return "A. Policy enforcement prototype"


def main() -> int:
    root = Path(sys.argv[1])
    records = load_records(root)
    passed = sum(1 for r in records if r["pass"])
    failed = len(records) - passed
    cls = classification(records)

    write(root, "validation_report.md", f"""# SYNTRIASS Validation Report

Records: {len(records)}
Passed: {passed}
Failed: {failed}

Current classification:

**{cls}**

{table(records)}
""")

    plaintext = [r for r in records if r["plaintext_marker_observed"]]
    write(root, "packet_capture_report.md", f"""# Packet Capture Report

PCAP files are under `{root / 'pcap'}`.

Plaintext marker observations: {len(plaintext)}

Baseline PCAP: `{root / 'pcap' / 'baseline_plaintext_before_syntriass.pcap'}`

{table(plaintext) if plaintext else 'No plaintext marker observed in successful captured flows.'}
""")

    missing_audit = [r for r in records if not r["audit_present"]]
    write(root, "audit_report.md", f"""# Audit Report

Audit log: `{root / 'audit' / 'syntriass-daemon.jsonl'}`

Connection attempts without audit records: {len(missing_audit)}

{table(missing_audit) if missing_audit else 'Every recorded attempt had at least one audit line.'}
""")

    write(root, "security_findings.md", f"""# Security Findings

- Generated from validation evidence only.
- Failed matrix entries require investigation before claiming PQC migration behavior.
- Successful connections with plaintext marker visible in PCAP fail the core thesis.
- Successful policy-only connections without a session fail Phase 3.
""")

    write(root, "operational_findings.md", f"""# Operational Findings

- Validation requires root, cgroup v2, eBPF load support, tcpdump, and pinned BPF maps.
- `socket_cookie` availability is mandatory for Phase 3 session binding.
- If retries receive a different socket cookie, Scenario A will fail until session binding is tied to the actual socket lifecycle.
- Performance data, when available, is stored in `{root / 'performance.jsonl'}`.
- Adversarial data, when available, is stored in `{root / 'adversarial.jsonl'}`.
""")

    trl = "TRL 3" if cls.startswith("A.") else "TRL 4"
    write(root, "trl_reassessment.md", f"""# TRL Reassessment

Evidence-based classification: **{cls}**

Recommended TRL: **{trl}**

Rationale:
- TRL 3 if validation only proves source-level or partial policy enforcement.
- TRL 4 only if the Linux lab run proves kernel enforcement plus session-gated success and no plaintext application data in PCAP.
""")
    print(root / "report" / "validation_report.md")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
