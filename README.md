# HIPAA Security Rule Audit & Configuration Monitoring Suite

![CI](https://github.com/griddyaf/hipaa-audit-suite/actions/workflows/ci.yml/badge.svg) ![Security](https://github.com/griddyaf/hipaa-audit-suite/actions/workflows/security.yml/badge.svg) ![CodeQL](https://github.com/griddyaf/hipaa-audit-suite/actions/workflows/codeql.yml/badge.svg)

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
| Data at Rest (`auditors/data_at_rest.py`) | reads DB config JSON | connects to PostgreSQL / **MySQL (Cloud SQL)** / MongoDB and inspects SSL + encryption settings |
| Data in Transit (`auditors/data_in_transit.py`) | n/a | enumerates accepted TLS protocols (flags TLS 1.0/1.1); **detects Cloudflare edge** |
| Cloudflare zone (`config_checks/cloudflare_check.py`) | n/a | checks SSL mode (Full strict), min TLS, Always Use HTTPS, HSTS via Cloudflare API |
| Audit Controls (`log_monitors/audit_logger.py`) | sample JSON logs | ingests JSON / JSONL / **GCP Cloud Audit Logs** / AWS CloudTrail / syslog |
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

## Target stack notes (GCP + Cloud SQL MySQL + Cloudflare)

This suite includes checks tailored to a GCP-hosted app using Cloud SQL for
MySQL behind Cloudflare DNS:

**Cloud SQL MySQL.** Put connection params under a `mysql` key in `--db-config`
and run `--live-db`. The auditor checks `require_secure_transport`, the active
connection cipher, and `have_ssl`/`tls_version`. Note Cloud SQL **encrypts at
rest by default** (Google-managed keys), so the suite does not fail on at-rest;
instead it flags a reminder to confirm whether **CMEK** is required (CMEK must be
set at instance creation).

```bash
python audit_runner.py --live-db --db-config cloudsql.json --skip-tls
# cloudsql.json: {"mysql": {"host": "...", "user": "...", "password": "...", "database": "...", "ssl": true}}
```

**Cloudflare.** A public TLS scan only tests the Cloudflare **edge**, not the
GCP origin. The TLS scanner detects Cloudflare and warns accordingly. Audit the
zone directly:

```bash
export CLOUDFLARE_API_TOKEN=...        # Zone -> SSL and Certificates: Read
python audit_runner.py --cloudflare-zone <ZONE_ID> --skip-tls
```

It verifies SSL/TLS mode is **Full (strict)**, minimum TLS >= 1.2, Always Use
HTTPS, and HSTS.

**GCP Cloud Audit Logs.** Export Data Access logs from Cloud Logging and run:

```bash
python audit_runner.py --log-file audit_logs.json --log-format gcp_audit --skip-tls
```

## Machine-readable output & scoring

Alongside the PDF, emit JSON (dashboards/diffing) and SARIF 2.1.0 (GitHub
code-scanning):

```bash
python audit_runner.py --skip-tls --no-pdf --json-out findings.json --sarif-out findings.sarif
```

Each run prints a pass rate and a severity-weighted posture score.

## Extended cloud posture (optional)

```bash
# Wrap Prowler's GCP results (Cloud SQL / GCS / KMS / IAM) into the report
python audit_runner.py --prowler-file prowler-output.ocsf.json --skip-tls --no-pdf
python audit_runner.py --run-prowler --gcp-project my-project --skip-tls   # runs prowler CLI

# Audit GCS buckets (public access, UBLA, PAP, versioning, retention, CMEK)
python audit_runner.py --gcs --gcp-project my-project --skip-tls --no-pdf

# Verify GCP Data Access audit logging is enabled
python audit_runner.py --check-audit-logging --gcp-project my-project --skip-tls --no-pdf

# Append manual-review reminders (automatic logoff, backup/contingency)
python audit_runner.py --manual-checklist --skip-tls --no-pdf
```

Deep TLS: the in-transit scanner now also flags weak negotiated ciphers
(RC4/3DES/etc.) and certificate expiry, in addition to protocol enumeration.

## Application-layer scanning (DAST/SAST)

Infra checks alone miss where most EMR HIPAA risk lives. These probe the running
app and its source:

```bash
# Active HTTP security-header grade (CSP/HSTS/X-Frame/etc.; flags unsafe-inline)
python audit_runner.py --headers-url https://portal.example.com --skip-tls --no-pdf

# Authenticated IDOR / cross-tenant authorization probe (config-driven)
python audit_runner.py --idor-config idor.json --skip-tls --no-pdf

# Node dependency vulnerabilities
python audit_runner.py --npm-audit-file npm-audit.json --skip-tls --no-pdf   # ingest
python audit_runner.py --npm-audit-dir ./member-app --skip-tls --no-pdf       # live

# Static scan for swallowed audit-log writes (HIPAA audit-trail loss)
python audit_runner.py --audit-write-scan ./member-app/src --skip-tls --no-pdf
```

# Tier-2 source SAST: SQLi / SSRF / upload safety / CSRF coverage / MFA posture
python audit_runner.py --sast-scan ./member-app --skip-tls --no-pdf
```

These are heuristic *review indicators*: direct SQL interpolation and plaintext
MFA secrets are flagged as failures; dynamic SQL, server-side fetch of non-literal
URLs, unsanitized upload keys, and mutating routes outside CSRF-protected prefixes
are flagged for review.

```bash

IDOR config shape:

```json
{
  "base_url": "https://portal.example.com",
  "probes": [
    {"name": "patient B record via A session", "method": "GET",
     "path": "/api/portal/patients/{victim_id}", "victim_id": "uuid-of-B",
     "victim_marker": "Bob Smith",
     "headers": {"Cookie": "next-auth.session-token=<patient-A-session>"}}
  ]
}
```

Tokens/cookies are supplied at runtime and never stored. Run only against
systems you are authorized to test.

## CI / security automation

GitHub Actions in `.github/workflows/`:

- **ci.yml** — ruff lint + pytest across Python 3.10/3.11/3.12.
- **codeql.yml** — CodeQL security-and-quality analysis.
- **security.yml** — Bandit SAST (SARIF to code scanning), pip-audit dependency
  scan, gitleaks secret scan, and a mock run of the suite itself (SARIF + JSON
  artifacts).
- **dependabot.yml** — weekly pip + github-actions updates.

Local equivalents:

```bash
pip install -e ".[dev]"
ruff check . && pytest -q && bandit -r . -c pyproject.toml && pip-audit -r requirements.txt
```

## Tests

```bash
pip install pytest && python -m pytest tests/ -q
```

The suite is hermetic (no external network): it includes a local TLS server to
exercise the protocol scanner.
