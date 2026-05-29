"""Data-at-Rest auditor.

Two modes:
  * mock  – read a JSON file describing DB encryption settings (offline demo).
  * live  – connect to a real PostgreSQL/MongoDB instance and inspect the
            encryption/SSL settings that are actually queryable in-band.

Drivers (psycopg2/pymongo) are imported lazily so the suite runs in mock
mode without them installed.
"""
import json
import os

from hipaa_refs import ERROR, FAIL, PASS, WARN, make_finding


def evaluate_mysql_tls(variables, status, label="Database: MySQL"):
    """Pure evaluation of MySQL TLS posture from server variables/status.

    variables: dict from SHOW VARIABLES (e.g. require_secure_transport, have_ssl,
               tls_version). status: dict from SHOW STATUS (e.g. Ssl_cipher).
    Returns a list of findings. Kept pure so it is unit-testable without a DB.
    """
    findings = []
    rst = str(variables.get("require_secure_transport", "")).upper()
    if rst in ("ON", "1", "YES"):
        findings.append(make_finding(
            PASS, label, "Server enforces encrypted transport (require_secure_transport=ON).",
            "encryption_in_transit"))
    else:
        findings.append(make_finding(
            FAIL, label,
            "require_secure_transport is OFF; server accepts unencrypted client connections to PHI.",
            "encryption_in_transit"))

    cipher = status.get("Ssl_cipher") or ""
    if cipher:
        findings.append(make_finding(
            PASS, label, f"Current connection is TLS-encrypted (cipher {cipher}).",
            "transmission_security"))
    else:
        findings.append(make_finding(
            WARN, label,
            "Audit connection itself was not TLS-encrypted; verify clients connect with SSL.",
            "transmission_security"))

    # Cloud SQL encrypts at rest by default; CMEK is the addressable control.
    findings.append(make_finding(
        WARN, label,
        "Cloud SQL encrypts data at rest by default (Google-managed keys). "
        "Confirm whether customer-managed keys (CMEK) are required by your risk analysis; "
        "CMEK must be set at instance creation.",
        "encryption_at_rest"))
    return findings


class DataAtRestAuditor:
    def __init__(self, config_path="mock_data/db_configs.json", live=False):
        self.config_path = config_path
        self.live = live
        self.findings = []

    # ------------------------------------------------------------------ #
    def run_audit(self):
        if self.live:
            return self._run_live()
        return self._run_mock()

    # ----------------------------- mock ------------------------------- #
    def _run_mock(self):
        if not os.path.exists(self.config_path):
            self.findings.append(make_finding(
                ERROR, "Data At Rest Auditor",
                f"Configuration file not found at {self.config_path}",
                "config_error"))
            return self.findings
        try:
            with open(self.config_path) as f:
                configs = json.load(f)
        except json.JSONDecodeError:
            self.findings.append(make_finding(
                ERROR, "Data At Rest Auditor",
                "Invalid JSON in configuration file", "config_error"))
            return self.findings

        for engine, label in (("postgresql", "PostgreSQL"), ("mysql", "MySQL"), ("mongodb", "MongoDB")):
            if engine not in configs:
                continue
            if configs[engine].get("encryption_at_rest"):
                self.findings.append(make_finding(
                    PASS, f"Database: {label}",
                    "Encryption at rest is enabled.", "encryption_at_rest"))
            else:
                self.findings.append(make_finding(
                    FAIL, f"Database: {label}",
                    "Encryption at rest is DISABLED. Volume/TDE encryption required for PHI.",
                    "encryption_at_rest"))
        if not self.findings:
            self.findings.append(make_finding(
                WARN, "Data At Rest Auditor",
                "No known database engines found in config.", "config_error"))
        return self.findings

    # ----------------------------- live ------------------------------- #
    def _run_live(self):
        cfg = {}
        if self.config_path and os.path.exists(self.config_path):
            try:
                with open(self.config_path) as f:
                    cfg = json.load(f)
            except json.JSONDecodeError:
                pass
        if "postgresql" in cfg:
            self._audit_postgres(cfg["postgresql"])
        if "mysql" in cfg:
            self._audit_mysql(cfg["mysql"])
        if "mongodb" in cfg:
            self._audit_mongodb(cfg["mongodb"])
        if not self.findings:
            self.findings.append(make_finding(
                ERROR, "Data At Rest Auditor",
                "Live mode requested but no connection params provided.", "config_error"))
        return self.findings

    def _audit_postgres(self, conn):
        label = "Database: PostgreSQL"
        try:
            import psycopg2  # lazy
        except ImportError:
            self.findings.append(make_finding(
                ERROR, label, "psycopg2 not installed; cannot run live check.", "config_error"))
            return
        try:
            c = psycopg2.connect(
                host=conn.get("host", "localhost"),
                port=conn.get("port", 5432),
                dbname=conn.get("database", "postgres"),
                user=conn.get("user"),
                password=conn.get("password"),
                sslmode=conn.get("ssl_mode", "prefer"),
                connect_timeout=conn.get("timeout", 5),
            )
        except Exception as exc:  # noqa: BLE001
            self.findings.append(make_finding(
                ERROR, label, f"Connection failed: {exc}", "config_error"))
            return
        try:
            cur = c.cursor()
            cur.execute("SHOW ssl;")
            ssl_on = (cur.fetchone()[0] == "on")
            if ssl_on:
                self.findings.append(make_finding(
                    PASS, label, "Server enforces SSL for client connections.",
                    "encryption_in_transit"))
            else:
                self.findings.append(make_finding(
                    FAIL, label, "SSL is OFF; client traffic to PHI store is unencrypted.",
                    "encryption_in_transit"))
            # TDE/volume encryption is not queryable via SQL in stock Postgres.
            self.findings.append(make_finding(
                WARN, label,
                "Encryption-at-rest (volume/TDE) cannot be verified in-band; "
                "confirm disk/volume encryption at the infrastructure layer.",
                "encryption_at_rest"))
        finally:
            c.close()

    def _audit_mysql(self, conn):
        label = "Database: MySQL"
        try:
            import pymysql  # lazy
        except ImportError:
            self.findings.append(make_finding(
                ERROR, label, "PyMySQL not installed; cannot run live check.", "config_error"))
            return
        try:
            ssl_arg = {"ssl": {}} if conn.get("ssl", True) else {}
            c = pymysql.connect(
                host=conn.get("host", "localhost"),
                port=int(conn.get("port", 3306)),
                user=conn.get("user"),
                password=conn.get("password"),
                database=conn.get("database"),
                connect_timeout=conn.get("timeout", 5),
                **ssl_arg,
            )
        except Exception as exc:  # noqa: BLE001
            self.findings.append(make_finding(
                ERROR, label, f"Connection failed: {exc}", "config_error"))
            return
        try:
            cur = c.cursor()
            variables = {}
            for var in ("require_secure_transport", "have_ssl", "tls_version"):
                cur.execute("SHOW VARIABLES LIKE %s;", (var,))
                row = cur.fetchone()
                if row:
                    variables[row[0]] = row[1]
            cur.execute("SHOW STATUS LIKE 'Ssl_cipher';")
            row = cur.fetchone()
            status = {row[0]: row[1]} if row else {}
            self.findings.extend(evaluate_mysql_tls(variables, status, label))
        finally:
            c.close()

    def _audit_mongodb(self, conn):
        label = "Database: MongoDB"
        try:
            from pymongo import MongoClient  # lazy
        except ImportError:
            self.findings.append(make_finding(
                ERROR, label, "pymongo not installed; cannot run live check.", "config_error"))
            return
        uri = conn.get("uri") or "mongodb://{}:{}/".format(
            conn.get("host", "localhost"), conn.get("port", 27017))
        try:
            client = MongoClient(uri, serverSelectionTimeoutMS=conn.get("timeout_ms", 5000))
            opts = client.admin.command("getCmdLineOpts")
        except Exception as exc:  # noqa: BLE001
            self.findings.append(make_finding(
                ERROR, label, f"Connection failed: {exc}", "config_error"))
            return
        parsed = opts.get("parsed", {})
        sec = parsed.get("security", {})
        if sec.get("enableEncryption"):
            self.findings.append(make_finding(
                PASS, label, "WiredTiger encryption at rest is enabled.",
                "encryption_at_rest"))
        else:
            self.findings.append(make_finding(
                FAIL, label,
                "Encryption at rest not enabled in mongod security config. "
                "Required for PHI (enable WiredTiger encryption or volume encryption).",
                "encryption_at_rest"))
        net = parsed.get("net", {}).get("tls", parsed.get("net", {}).get("ssl", {}))
        if isinstance(net, dict) and net.get("mode") in ("requireTLS", "requireSSL"):
            self.findings.append(make_finding(
                PASS, label, "TLS required for client connections.", "encryption_in_transit"))
        client.close()


if __name__ == "__main__":
    print(DataAtRestAuditor("../mock_data/db_configs.json").run_audit())
