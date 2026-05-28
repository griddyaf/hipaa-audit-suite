import argparse
import os
import sys

# Ensure the parent directory is in the path so we can import modules
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from auditors.data_at_rest import DataAtRestAuditor
from auditors.data_in_transit import DataInTransitAuditor
from log_monitors.audit_logger import AuditLogMonitor
from config_checks.access_control import AccessControlAuditor
from compliance_reports.report_generator import ReportGenerator

def main():
    parser = argparse.ArgumentParser(description="Run the HIPAA Security Rule Audit Suite.")
    parser.add_argument("--target-url", type=str, default="https://localhost", help="The target URL to scan for TLS compliance (Data in Transit).")
    parser.add_argument("--db-config", type=str, default="mock_data/db_configs.json", help="Path to the database configuration JSON.")
    parser.add_argument("--log-file", type=str, default="mock_data/sample_logs.json", help="Path to the application access logs JSON.")
    parser.add_argument("--iam-config", type=str, default="mock_data/sample_iam.json", help="Path to the IAM roles configuration JSON.")
    parser.add_argument("--output", type=str, default="HIPAA_Compliance_Report.pdf", help="Output path for the generated PDF report.")

    args = parser.parse_args()

    print("Starting HIPAA Security Rule Audit...")
    all_findings = []

    # 1. Data at Rest (Encryption)
    print("[*] Running Data at Rest Auditor...")
    dar_auditor = DataAtRestAuditor(args.db_config)
    all_findings.extend(dar_auditor.run_audit())

    # 2. Data in Transit (TLS)
    print(f"[*] Running Data in Transit Auditor against {args.target_url}...")
    dit_auditor = DataInTransitAuditor(args.target_url)
    all_findings.extend(dit_auditor.run_audit())

    # 3. Audit Controls (Logs)
    print("[*] Running Audit Controls Monitor...")
    log_auditor = AuditLogMonitor(args.log_file)
    all_findings.extend(log_auditor.run_audit())

    # 4. Access Control (IAM)
    print("[*] Running Access Control Auditor...")
    iam_auditor = AccessControlAuditor(args.iam_config)
    all_findings.extend(iam_auditor.run_audit())

    # Generate Report
    print(f"[*] Generating compliance report at {args.output}...")
    report_gen = ReportGenerator(all_findings, args.output)
    report_gen.generate_report()
    
    print("Audit complete.")

if __name__ == "__main__":
    main()
