"""Test suite for the HIPAA Audit Suite (mock/hermetic — no external network)."""
import json
import os
import socket
import ssl
import subprocess
import sys
import threading

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from auditors.data_at_rest import DataAtRestAuditor
from auditors.data_in_transit import DataInTransitAuditor
from compliance_reports.report_generator import ReportGenerator
from config_checks.access_control import AccessControlAuditor
from hipaa_refs import make_finding
from log_monitors.audit_logger import AuditLogMonitor
from security import ValidationError, validate_config_path, validate_target_url

MOCK = os.path.join(ROOT, "mock_data")
HERE = os.path.dirname(__file__)


# ----------------------------- hipaa_refs ----------------------------- #
def test_make_finding_attaches_citation():
    f = make_finding("FAIL", "DB", "no encryption", "encryption_at_rest")
    assert f["citation"].startswith("45 CFR")
    assert f["severity"] == "high"


# ------------------------------ security ------------------------------ #
def test_validate_target_url_blocks_private():
    with pytest.raises(ValidationError):
        validate_target_url("http://127.0.0.1/")
    with pytest.raises(ValidationError):
        validate_target_url("ftp://example.com")


def test_validate_target_url_allow_private():
    host, port = validate_target_url("https://localhost:8443", allow_private=True)
    assert host == "localhost" and port == 8443


def test_validate_config_path_blocks_traversal():
    with pytest.raises(ValidationError):
        validate_config_path("../../etc/passwd", MOCK)
    ok = validate_config_path("db_configs.json", MOCK)
    assert ok.endswith("db_configs.json")


# --------------------------- data at rest ----------------------------- #
def test_data_at_rest_mock_pass_and_fail():
    findings = DataAtRestAuditor(os.path.join(MOCK, "db_configs.json")).run_audit()
    statuses = {f["component"]: f["status"] for f in findings}
    assert statuses["Database: PostgreSQL"] == "PASS"
    assert statuses["Database: MongoDB"] == "FAIL"


def test_data_at_rest_missing_file():
    findings = DataAtRestAuditor("nope.json").run_audit()
    assert findings[0]["status"] == "ERROR"


# --------------------------- access control --------------------------- #
def test_access_control_file_mode():
    findings = AccessControlAuditor(os.path.join(MOCK, "sample_iam.json")).run_audit()
    by_role = {f["component"]: f["status"] for f in findings}
    assert by_role["IAM Role: nurse"] == "FAIL"   # has manage_users
    assert by_role["IAM Role: patient"] == "FAIL"  # has write_all
    assert by_role["IAM Role: doctor"] == "PASS"


def test_gcp_binding_evaluation_dict():
    a = AccessControlAuditor(mode="gcp", project_id="x")
    a._evaluate_bindings([
        {"role": "roles/owner", "members": ["user:bob@example.com"]},
        {"role": "roles/viewer", "members": ["allUsers"]},
    ])
    fails = [f for f in a.findings if f["status"] == "FAIL"]
    assert any("Primitive role" in f["finding"] for f in fails)
    assert any("Public/anonymous" in f["finding"] for f in fails)


def test_gcp_binding_clean():
    a = AccessControlAuditor(mode="gcp", project_id="x")
    a._evaluate_bindings([{"role": "roles/storage.objectViewer",
                           "members": ["user:bob@example.com"]}])
    assert a.findings[0]["status"] == "PASS"


# ------------------------------- logs --------------------------------- #
def test_logs_json_detects_violations():
    findings = AuditLogMonitor(os.path.join(MOCK, "sample_logs.json")).run_audit()
    assert any(f["status"] == "FAIL" for f in findings)


def test_logs_jsonl():
    findings = AuditLogMonitor(os.path.join(HERE, "mock_logs.jsonl")).run_audit()
    assert any("anonymous" in f["finding"].lower() or "unauthenticated" in f["finding"].lower()
               for f in findings if f["status"] == "FAIL")


def test_logs_cloudtrail_missing_user():
    findings = AuditLogMonitor(os.path.join(HERE, "mock_cloudtrail.json")).run_audit()
    assert any(f["status"] == "FAIL" and "user_id" in f["finding"] for f in findings)


# ------------------------------ report -------------------------------- #
def test_report_generation(tmp_path):
    out = tmp_path / "r.pdf"
    findings = [make_finding("PASS", "x", "ok", "audit_controls"),
                make_finding("FAIL", "y", "bad", "encryption_at_rest")]
    ReportGenerator(findings, str(out)).generate_report()
    assert out.exists() and out.stat().st_size > 500


# --------------------------- live TLS (local) ------------------------- #
@pytest.fixture(scope="module")
def tls12_server():
    """Spin up a localhost TLS-1.2-max server with a self-signed cert."""
    import tempfile
    d = tempfile.mkdtemp()
    cert, key = os.path.join(d, "c.pem"), os.path.join(d, "k.pem")
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-keyout", key,
         "-out", cert, "-days", "1", "-nodes", "-subj", "/CN=localhost"],
        check=True, capture_output=True)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(cert, key)
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(5)
    port = srv.getsockname()[1]
    stop = threading.Event()

    def serve():
        srv.settimeout(0.5)
        while not stop.is_set():
            try:
                conn, _ = srv.accept()
            except socket.timeout:
                continue
            try:
                with ctx.wrap_socket(conn, server_side=True) as s:
                    s.recv(16)
            except (ssl.SSLError, OSError):
                pass
    t = threading.Thread(target=serve, daemon=True)
    t.start()
    yield port
    stop.set()
    t.join(timeout=2)
    srv.close()


def test_tls_scan_local_server_strong(tls12_server):
    url = f"https://127.0.0.1:{tls12_server}"
    findings = DataInTransitAuditor(url, allow_private=True).run_audit()
    statuses = [f["status"] for f in findings]
    assert "PASS" in statuses
    assert "FAIL" not in statuses  # TLS 1.2 only -> no weak-protocol failures
