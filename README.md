# HIPAA Security Rule Audit & Configuration Monitoring Suite

A defensive compliance verification tool that automates checking of technical
safeguards required under the HIPAA Security Rule (45 CFR Part 164, Subpart C).
It audits database encryption, TLS transmission security, audit-control logging,
and IAM least-privilege, then produces a cited PDF report.

> **Disclaimer:** This is an automated technical assessment aid. It does **not**
> constitute legal advice or a certification of HIPAA compliance.

## Modes

Every check runs in either an offline **mock** mode (bundled JSON fixtures, great
for demos/CI) or a **live** mode that connects to real infrastructure.

| Module | Mock | Live |
|---|---|---|
| Data at Rest (`auditors/data_at_rest.py`) | reads DB config JSON | connects to PostgreSQL/MongoDB and inspects SSL + encryption settings |
| Data in Transit (`auditors/data_in_transit.py`) | n/a | enumerates accepted TLS protocols against an endpoint (flags TLS 1.0/1.1) |
| Audit Controls (`log_monitors/audit_logger.py`) | sample JSON logs | ingests JSON / JSONL / AWS CloudTrail / syslog |
| Access Control (`config_checks/access_control.py`) | role→permission JSON | pulls live **GCP** IAM policy and flags primitive roles + public members |
| Report (`compliance_reports/report_generator.py`) | — | PDF via ReportLab, with HIPAA citations per finding |

Each finding carries a `citation` (e.g. `45 CFR §164.312(e)(2)(ii)`) and a
`severity`.

## Installation

```bash
pip install -r requirements.txt          # core: reporting + web UI + TLS scan
pip install -r requirements-live.txt      # optional: Postgres/Mongo/GCP drivers
```

Python 3.10+.

## CLI usage

```bash
python audit_runner.py --help
```

Offline demo against bundled mock data:

```bash
python audit_runner.py --skip-tls            # all mock checks, no network
python audit_runner.py --target-url https://example.com --output Report.pdf
```

Live examples:

```bash
# Live Postgres/Mongo (connection params read from --db-config JSON)
python audit_runner.py --live-db --db-config prod_db.json --skip-tls

# Live GCP IAM least-privilege
python audit_runner.py --iam-mode gcp --gcp-project my-project --skip-tls

# Real CloudTrail log ingestion
python audit_runner.py --log-file trail.json --log-format cloudtrail --skip-tls
```

`--allow-private` permits scanning loopback/private targets (local testing only;
otherwise such targets are blocked to prevent SSRF).

### Live credentials

- **PostgreSQL/MongoDB:** put host/port/user/password (or a `uri`) in the
  `--db-config` JSON.
- **GCP:** uses Application Default Credentials
  (`gcloud auth application-default login` or `GOOGLE_APPLICATION_CREDENTIALS`).
  Needs `resourcemanager.projects.getIamPolicy`.

## Web UI

```bash
python app.py            # serves on 127.0.0.1:5001
```

Environment knobs: `FLASK_DEBUG`, `AUDIT_HOST`, `AUDIT_PORT`, `AUDIT_DATA_ROOT`
(restricts which files the API may read), `AUDIT_ALLOW_PRIVATE`. Debug is **off**
by default and config-file inputs are confined to `AUDIT_DATA_ROOT` to prevent
path traversal; target URLs are validated to prevent SSRF.

## Tests

```bash
pip install pytest && python -m pytest tests/ -q
```

The suite is hermetic (no external network): it includes a local TLS server to
exercise the protocol scanner.
