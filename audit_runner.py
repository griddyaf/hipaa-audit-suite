"""CLI orchestrator for the HIPAA Audit Suite."""
import argparse
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from auditors.data_at_rest import DataAtRestAuditor
from auditors.data_in_transit import DataInTransitAuditor
from compliance_reports.report_generator import ReportGenerator
from config_checks.access_control import AccessControlAuditor
from log_monitors.audit_logger import AuditLogMonitor


def build_parser():
    p = argparse.ArgumentParser(description="Run the HIPAA Security Rule Audit Suite.")
    p.add_argument("--target-url", default="https://localhost",
                   help="Endpoint to scan for TLS compliance.")
    p.add_argument("--allow-private", action="store_true",
                   help="Permit scanning private/loopback targets (local testing only).")
    p.add_argument("--db-config", default="mock_data/db_configs.json",
                   help="Path to database configuration JSON (and live connection params).")
    p.add_argument("--live-db", action="store_true",
                   help="Connect to real databases instead of reading mock config.")
    p.add_argument("--log-file", default="mock_data/sample_logs.json",
                   help="Path to application access logs.")
    p.add_argument("--log-format", default="auto",
                   choices=["auto", "json", "jsonl", "cloudtrail", "gcp_audit", "syslog"],
                   help="Log format (default auto-detect).")
    p.add_argument("--iam-config", default="mock_data/sample_iam.json",
                   help="Path to IAM roles JSON (file mode).")
    p.add_argument("--iam-mode", default="file", choices=["file", "gcp"],
                   help="Access-control source: local file or live GCP IAM.")
    p.add_argument("--gcp-project", default=None,
                   help="GCP project ID (required when --iam-mode gcp).")
    p.add_argument("--cloudflare-zone", default=None,
                   help="Cloudflare zone ID to audit (token via CLOUDFLARE_API_TOKEN env).")
    p.add_argument("--prowler-file", default=None,
                   help="Ingest an existing Prowler JSON/OCSF results file.")
    p.add_argument("--run-prowler", action="store_true",
                   help="Run the prowler CLI live (requires prowler installed + GCP creds).")
    p.add_argument("--gcs", action="store_true",
                   help="Audit GCS buckets (requires google-cloud-storage + --gcp-project).")
    p.add_argument("--check-audit-logging", action="store_true",
                   help="Verify GCP Data Access audit logging is enabled (needs --gcp-project).")
    p.add_argument("--manual-checklist", action="store_true",
                   help="Append reminders for safeguards requiring human verification.")
    p.add_argument("--headers-url", default=None,
                   help="Actively grade HTTP security headers of this URL (DAST).")
    p.add_argument("--idor-config", default=None,
                   help="JSON config for the authenticated IDOR/authorization probe (DAST).")
    p.add_argument("--npm-audit-file", default=None,
                   help="Ingest an existing `npm audit --json` results file.")
    p.add_argument("--npm-audit-dir", default=None,
                   help="Run `npm audit` live in this Node project directory.")
    p.add_argument("--audit-write-scan", default=None,
                   help="Static scan of a source dir for swallowed audit-log writes (SAST).")
    p.add_argument("--sast-scan", default=None,
                   help="Tier-2 source SAST (SQLi/SSRF/upload/CSRF/MFA) over a source dir.")
    p.add_argument("--output", default="HIPAA_Compliance_Report.pdf",
                   help="Output path for the generated PDF report.")
    p.add_argument("--json-out", default=None, help="Also write findings as JSON.")
    p.add_argument("--sarif-out", default=None,
                   help="Also write findings as SARIF 2.1.0 (for GitHub code-scanning).")
    p.add_argument("--no-pdf", action="store_true", help="Skip PDF generation.")
    p.add_argument("--skip-tls", action="store_true", help="Skip the TLS scan.")
    return p


def run_all(args):
    findings = []
    print("[*] Data at Rest...")
    findings += DataAtRestAuditor(args.db_config, live=args.live_db).run_audit()

    if not args.skip_tls:
        print(f"[*] Data in Transit against {args.target_url}...")
        findings += DataInTransitAuditor(
            args.target_url, allow_private=args.allow_private).run_audit()

    print("[*] Audit Controls (logs)...")
    findings += AuditLogMonitor(args.log_file, fmt=args.log_format).run_audit()

    print(f"[*] Access Control ({args.iam_mode})...")
    findings += AccessControlAuditor(
        args.iam_config, mode=args.iam_mode, project_id=args.gcp_project).run_audit()

    if args.cloudflare_zone:
        print("[*] Cloudflare zone settings...")
        from config_checks.cloudflare_check import CloudflareAuditor
        findings += CloudflareAuditor(args.cloudflare_zone).run_audit()

    if args.gcs:
        print("[*] GCS buckets...")
        from config_checks.gcs_check import GCSAuditor
        findings += GCSAuditor(project_id=args.gcp_project).run_audit()

    if args.check_audit_logging:
        print("[*] GCP audit logging config...")
        from config_checks.gcp_audit_config import GCPAuditLoggingAuditor
        findings += GCPAuditLoggingAuditor(project_id=args.gcp_project).run_audit()

    if args.prowler_file or args.run_prowler:
        print("[*] Prowler findings...")
        from integrations.prowler_ingest import ProwlerAuditor
        findings += ProwlerAuditor(
            provider="gcp", project=args.gcp_project,
            results_file=args.prowler_file, run=args.run_prowler).run_audit()

    if args.headers_url:
        print("[*] HTTP security headers...")
        from auditors.security_headers import SecurityHeaderAuditor
        findings += SecurityHeaderAuditor(args.headers_url,
                                          allow_private=args.allow_private).run_audit()

    if args.idor_config:
        print("[*] IDOR / authorization probe...")
        from auditors.idor_probe import IDORAuditor
        findings += IDORAuditor(config_path=args.idor_config,
                                allow_private=args.allow_private).run_audit()

    if args.npm_audit_file or args.npm_audit_dir:
        print("[*] npm dependency audit...")
        from integrations.npm_audit import NpmAuditAuditor
        findings += NpmAuditAuditor(project_dir=args.npm_audit_dir,
                                    results_file=args.npm_audit_file).run_audit()

    if args.audit_write_scan:
        print("[*] Audit-write reliability scan...")
        from config_checks.audit_write_scan import AuditWriteScanner
        findings += AuditWriteScanner(args.audit_write_scan).run_audit()

    if args.sast_scan:
        print("[*] Tier-2 SAST scan...")
        from config_checks.sast_scans import SASTScanner
        findings += SASTScanner(args.sast_scan).run_audit()

    if args.manual_checklist:
        findings += manual_checklist()
    return findings


def manual_checklist():
    """Safeguards that require human verification, surfaced as reminders."""
    from hipaa_refs import make_finding
    return [
        make_finding("WARN", "Manual Review",
                     "Confirm automatic logoff / session timeout is configured on systems with ePHI.",
                     "automatic_logoff"),
        make_finding("WARN", "Manual Review",
                     "Confirm a tested data backup & disaster-recovery plan exists for ePHI.",
                     "contingency_backup"),
    ]


def main(argv=None):
    args = build_parser().parse_args(argv)
    print("Starting HIPAA Security Rule Audit...")
    findings = run_all(args)
    if not args.no_pdf:
        print(f"[*] Generating report at {args.output}...")
        ReportGenerator(findings, args.output).generate_report()
    if args.json_out:
        from outputs import write_json
        write_json(findings, args.json_out)
        print(f"[*] Wrote JSON to {args.json_out}")
    if args.sarif_out:
        from outputs import write_sarif
        write_sarif(findings, args.sarif_out)
        print(f"[*] Wrote SARIF to {args.sarif_out}")
    from outputs import compliance_summary
    s = compliance_summary(findings)
    print(f"Audit complete. Pass rate: {s['pass_rate']}% | "
          f"posture score: {s['posture_score']} | "
          f"FAIL={s['counts']['FAIL']} WARN={s['counts']['WARN']} ERROR={s['counts']['ERROR']}")
    return findings


if __name__ == "__main__":
    main()
