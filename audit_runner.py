"""CLI orchestrator for the HIPAA Audit Suite."""
import argparse
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from auditors.data_at_rest import DataAtRestAuditor
from auditors.data_in_transit import DataInTransitAuditor
from config_checks.access_control import AccessControlAuditor
from compliance_reports.report_generator import ReportGenerator
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
                   choices=["auto", "json", "jsonl", "cloudtrail", "syslog"],
                   help="Log format (default auto-detect).")
    p.add_argument("--iam-config", default="mock_data/sample_iam.json",
                   help="Path to IAM roles JSON (file mode).")
    p.add_argument("--iam-mode", default="file", choices=["file", "gcp"],
                   help="Access-control source: local file or live GCP IAM.")
    p.add_argument("--gcp-project", default=None,
                   help="GCP project ID (required when --iam-mode gcp).")
    p.add_argument("--output", default="HIPAA_Compliance_Report.pdf",
                   help="Output path for the generated PDF report.")
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
    return findings


def main(argv=None):
    args = build_parser().parse_args(argv)
    print("Starting HIPAA Security Rule Audit...")
    findings = run_all(args)
    print(f"[*] Generating report at {args.output}...")
    ReportGenerator(findings, args.output).generate_report()
    print("Audit complete.")
    return findings


if __name__ == "__main__":
    main()
