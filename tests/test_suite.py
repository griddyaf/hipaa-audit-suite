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
            except TimeoutError:
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


# ====================== Cloud SQL MySQL + Cloudflare + GCP ============= #
from auditors.data_at_rest import evaluate_mysql_tls
from auditors.data_in_transit import detect_cloudflare
from config_checks.cloudflare_check import evaluate_cloudflare_settings


def test_mysql_eval_requires_secure_transport():
    on = evaluate_mysql_tls({"require_secure_transport": "ON"}, {"Ssl_cipher": "TLS_AES_256"})
    assert any(f["status"] == "PASS" and "require_secure_transport" in f["finding"] for f in on)
    off = evaluate_mysql_tls({"require_secure_transport": "OFF"}, {})
    assert any(f["status"] == "FAIL" for f in off)
    # CMEK-at-rest reminder always present
    assert any("CMEK" in f["finding"] for f in off)


def test_mysql_eval_unencrypted_connection_warns():
    res = evaluate_mysql_tls({"require_secure_transport": "ON"}, {"Ssl_cipher": ""})
    assert any(f["status"] == "WARN" and "not TLS-encrypted" in f["finding"] for f in res)


def test_detect_cloudflare():
    assert detect_cloudflare({"CF-RAY": "abc-LAX"}) is True
    assert detect_cloudflare({"Server": "cloudflare"}) is True
    assert detect_cloudflare({"Server": "gunicorn"}) is False
    assert detect_cloudflare({}) is False


def test_cloudflare_settings_eval():
    strict = evaluate_cloudflare_settings("strict", "1.2", "on", True)
    assert all(f["status"] == "PASS" for f in strict)
    flexible = evaluate_cloudflare_settings("flexible", "1.1", "off", False)
    statuses = [f["status"] for f in flexible]
    assert "FAIL" in statuses  # flexible mode + TLS 1.1
    assert statuses.count("FAIL") >= 2
    full = evaluate_cloudflare_settings("full", "1.2", "on", True)
    assert any(f["status"] == "WARN" and "not strict" in f["finding"] for f in full)


def test_gcp_audit_log_ingestion():
    findings = AuditLogMonitor(os.path.join(HERE, "mock_gcp_audit.json")).run_audit()
    # second entry has no principalEmail -> user_id missing -> FAIL
    assert any(f["status"] == "FAIL" and "user_id" in f["finding"] for f in findings)


def test_mysql_mock_mode_pass():
    findings = DataAtRestAuditor(os.path.join(MOCK, "db_configs.json")).run_audit()
    by = {f["component"]: f["status"] for f in findings}
    assert by["Database: MySQL"] == "PASS"


# ===================== OSS integrations + deep checks ================= #
from auditors.data_in_transit import classify_ciphers, evaluate_cert_expiry
from config_checks.gcp_audit_config import evaluate_audit_config
from config_checks.gcs_check import evaluate_bucket
from integrations.prowler_ingest import normalize_prowler_findings
from outputs import compliance_summary, to_sarif, write_json, write_sarif


def test_compliance_summary_and_score():
    fs = [make_finding("PASS", "a", "x", "audit_controls"),
          make_finding("FAIL", "b", "y", "encryption_at_rest"),
          make_finding("WARN", "c", "z", "integrity")]
    s = compliance_summary(fs)
    assert s["counts"]["FAIL"] == 1 and s["total"] == 3
    assert s["pass_rate"] == 50.0
    assert 0 <= s["posture_score"] <= 100


def test_sarif_structure_and_roundtrip(tmp_path):
    fs = [make_finding("FAIL", "DB", "bad", "encryption_at_rest")]
    sarif = to_sarif(fs)
    assert sarif["version"] == "2.1.0"
    run = sarif["runs"][0]
    assert run["results"][0]["level"] == "error"
    assert run["tool"]["driver"]["rules"]
    jp, sp = tmp_path / "f.json", tmp_path / "f.sarif"
    write_json(fs, str(jp))
    write_sarif(fs, str(sp))
    assert json.load(open(jp))["summary"]["total"] == 1
    assert json.load(open(sp))["version"] == "2.1.0"


def test_prowler_normalize_v3_and_v4():
    v3 = [{"Status": "FAIL", "CheckTitle": "Public IP", "Severity": "high",
           "ServiceName": "cloudsql", "ResourceId": "i1", "StatusExtended": "exposed"}]
    v4 = [{"status_code": "PASS", "severity": "Medium", "service_name": "storage",
           "finding_info": {"title": "UBLA on"}, "resources": [{"name": "gs://b"}]}]
    out = normalize_prowler_findings(v3) + normalize_prowler_findings(v4)
    assert out[0]["status"] == "FAIL" and out[0]["severity"] == "high"
    assert "cloudsql" in out[0]["component"]
    assert out[1]["status"] == "PASS"


def test_cert_expiry_eval():
    import time
    now = time.time()
    assert evaluate_cert_expiry(now - 86400, now)[0] == "FAIL"     # expired
    assert evaluate_cert_expiry(now + 10 * 86400, now)[0] == "WARN"  # soon
    assert evaluate_cert_expiry(now + 200 * 86400, now)[0] == "PASS"
    assert evaluate_cert_expiry(None, now)[0] == "WARN"


def test_classify_ciphers():
    weak = classify_ciphers(["ECDHE-RSA-RC4-SHA", "TLS_AES_256_GCM_SHA384", "DES-CBC3-SHA"])
    assert "ECDHE-RSA-RC4-SHA" in weak and "DES-CBC3-SHA" in weak
    assert "TLS_AES_256_GCM_SHA384" not in weak


def test_evaluate_bucket_public_and_retention():
    public = evaluate_bucket({"name": "phi", "public": True, "retention_period_seconds": 1000})
    assert any(f["status"] == "FAIL" and f["severity"] == "critical" for f in public)
    assert any(f["status"] == "FAIL" and "6 years" in f["finding"] for f in public)
    good = evaluate_bucket({
        "name": "ok", "public": False, "public_access_prevention": "enforced",
        "uniform_bucket_level_access": True, "versioning_enabled": True,
        "retention_period_seconds": 7 * 365 * 86400, "default_kms_key": "k"})
    assert all(f["status"] == "PASS" for f in good)


def test_evaluate_audit_config():
    missing = evaluate_audit_config([{"service": "allServices",
                                      "auditLogConfigs": [{"logType": "DATA_READ"}]}])
    assert missing[0]["status"] == "FAIL" and "DATA_WRITE" in missing[0]["finding"]
    full = evaluate_audit_config([{"service": "allServices", "auditLogConfigs": [
        {"logType": "DATA_READ"}, {"logType": "DATA_WRITE"}]}])
    assert full[0]["status"] == "PASS"
