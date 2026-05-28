from flask import Flask, render_template, request, jsonify, send_file
import os
import json

from auditors.data_at_rest import DataAtRestAuditor
from auditors.data_in_transit import DataInTransitAuditor
from log_monitors.audit_logger import AuditLogMonitor
from config_checks.access_control import AccessControlAuditor
from compliance_reports.report_generator import ReportGenerator

app = Flask(__name__, static_folder='static', static_url_path='')

@app.route('/')
def index():
    return app.send_static_file('index.html')

@app.route('/api/run-audit', methods=['POST'])
def run_audit():
    data = request.json
    target_url = data.get('target_url', 'https://localhost')
    db_config = data.get('db_config', 'mock_data/db_configs.json')
    log_file = data.get('log_file', 'mock_data/sample_logs.json')
    iam_config = data.get('iam_config', 'mock_data/sample_iam.json')
    
    output_pdf = "HIPAA_Compliance_Report.pdf"

    all_findings = []

    try:
        # 1. Data at Rest
        dar_auditor = DataAtRestAuditor(db_config)
        all_findings.extend(dar_auditor.run_audit())

        # 2. Data in Transit
        dit_auditor = DataInTransitAuditor(target_url)
        all_findings.extend(dit_auditor.run_audit())

        # 3. Logs
        log_auditor = AuditLogMonitor(log_file)
        all_findings.extend(log_auditor.run_audit())

        # 4. IAM
        iam_auditor = AccessControlAuditor(iam_config)
        all_findings.extend(iam_auditor.run_audit())

        # Generate Report
        report_gen = ReportGenerator(all_findings, output_pdf)
        report_gen.generate_report()

        return jsonify({"status": "success", "findings": all_findings, "report_url": "/api/download-report"})

    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/download-report', methods=['GET'])
def download_report():
    report_path = os.path.abspath("HIPAA_Compliance_Report.pdf")
    if os.path.exists(report_path):
        return send_file(report_path, as_attachment=True)
    return "Report not found", 404

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001, debug=True)
