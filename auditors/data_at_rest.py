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

from hipaa_refs import make_finding, PASS, FAIL, WARN, ERROR


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

        for engine, label in (("postgresql", "PostgreSQL"), ("mongodb", "MongoDB")):
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
