"""Flask web UI for the HIPAA Audit Suite (hardened)."""
import os
import tempfile
import uuid

from flask import Flask, jsonify, request, send_file

from auditors.data_at_rest import DataAtRestAuditor
from auditors.data_in_transit import DataInTransitAuditor
from compliance_reports.report_generator import ReportGenerator
from config_checks.access_control import AccessControlAuditor
from log_monitors.audit_logger import AuditLogMonitor
from security import ValidationError, validate_config_path, validate_target_url

app = Flask(__name__, static_folder="static", static_url_path="")

# Only files under this root may be referenced by API requests (anti-traversal).
DATA_ROOT = os.path.abspath(os.environ.get("AUDIT_DATA_ROOT", "mock_data"))
REPORT_DIR = tempfile.mkdtemp(prefix="hipaa_reports_")
# Allow private/loopback TLS targets only if explicitly enabled in the env.
ALLOW_PRIVATE = os.environ.get("AUDIT_ALLOW_PRIVATE", "").lower() in ("1", "true", "yes")
_REPORTS = {}  # report_id -> absolute path


@app.route("/")
def index():
    return app.send_static_file("index.html")


@app.route("/api/run-audit", methods=["POST"])
def run_audit():
    data = request.get_json(silent=True) or {}
    findings = []
    try:
        # Data at rest (mock config only via the web UI; live DB creds are CLI-only).
        db_config = validate_config_path(
            data.get("db_config", "db_configs.json"), DATA_ROOT)
        findings += DataAtRestAuditor(db_config).run_audit()

        # Data in transit – validate URL to prevent SSRF.
        target_url = data.get("target_url")
        if target_url:
            validate_target_url(target_url, allow_private=ALLOW_PRIVATE)
            findings += DataInTransitAuditor(
                target_url, allow_private=ALLOW_PRIVATE).run_audit()

        # Logs
        log_file = validate_config_path(
            data.get("log_file", "sample_logs.json"), DATA_ROOT)
        findings += AuditLogMonitor(log_file).run_audit()

        # Access control (file mode in web UI)
        iam_config = validate_config_path(
            data.get("iam_config", "sample_iam.json"), DATA_ROOT)
        findings += AccessControlAuditor(iam_config).run_audit()
    except ValidationError as exc:
        return jsonify({"status": "error", "message": str(exc)}), 400
    except Exception:  # noqa: BLE001
        return jsonify({"status": "error", "message": "internal error during audit"}), 500

    report_id = uuid.uuid4().hex
    report_path = os.path.join(REPORT_DIR, f"report_{report_id}.pdf")
    ReportGenerator(findings, report_path).generate_report()
    _REPORTS[report_id] = report_path

    return jsonify({
        "status": "success",
        "findings": findings,
        "report_url": f"/api/download-report/{report_id}",
    })


@app.route("/api/download-report/<report_id>", methods=["GET"])
def download_report(report_id):
    path = _REPORTS.get(report_id)
    if not path or not os.path.isfile(path):
        return jsonify({"status": "error", "message": "report not found"}), 404
    return send_file(path, as_attachment=True, download_name="HIPAA_Compliance_Report.pdf")


if __name__ == "__main__":
    debug = os.environ.get("FLASK_DEBUG", "").lower() in ("1", "true", "yes")
    host = os.environ.get("AUDIT_HOST", "127.0.0.1")
    port = int(os.environ.get("AUDIT_PORT", "5001"))
    app.run(host=host, port=port, debug=debug)
