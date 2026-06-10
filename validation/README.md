# SYNTRIASS Linux Validation Framework

This tree validates the current SYNTRIASS kernel enforcement thesis on Ubuntu
24.04 / Linux 6.x:

> An unmodified legacy TCP application can communicate only when an authorized
> PQC session exists, without application source-code changes.

The framework is evidence-driven. It produces PASS/FAIL results from process
exit codes, daemon audit JSON, and PCAP inspection. It does not assume success.

## Run

On an Ubuntu 24.04 VM with root:

```bash
sudo validation/scripts/setup_ubuntu24.sh
validation/scripts/build_all.sh
sudo validation/scripts/run_matrix.sh
python3 validation/scripts/generate_report.py validation/artifacts/latest
```

Primary outputs:

```text
validation/artifacts/latest/matrix.jsonl
validation/artifacts/latest/audit/syntriass-daemon.jsonl
validation/artifacts/latest/pcap/*.pcap
validation/artifacts/latest/report/validation_report.md
validation/artifacts/latest/report/packet_capture_report.md
validation/artifacts/latest/report/audit_report.md
validation/artifacts/latest/report/security_findings.md
validation/artifacts/latest/report/operational_findings.md
validation/artifacts/latest/report/trl_reassessment.md
```

## Expected Decision

The final report classifies the current system as:

```text
A. Policy enforcement prototype
B. PQC migration prototype
C. Functional PQC migration platform
D. Enterprise-ready migration product
```

The classification is generated from evidence only.
