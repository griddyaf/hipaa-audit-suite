import json
import os

class DataAtRestAuditor:
    def __init__(self, config_path):
        self.config_path = config_path
        self.findings = []

    def run_audit(self):
        """Runs the audit against the mock database configurations."""
        if not os.path.exists(self.config_path):
            self.findings.append({
                "status": "ERROR",
                "component": "Data At Rest Auditor",
                "finding": f"Configuration file not found at {self.config_path}"
            })
            return self.findings

        try:
            with open(self.config_path, 'r') as f:
                configs = json.load(f)
        except json.JSONDecodeError:
            self.findings.append({
                "status": "ERROR",
                "component": "Data At Rest Auditor",
                "finding": "Invalid JSON in configuration file"
            })
            return self.findings

        # Check Postgres
        if "postgresql" in configs:
            pg_config = configs["postgresql"]
            if pg_config.get("encryption_at_rest"):
                self.findings.append({
                    "status": "PASS",
                    "component": "Database: PostgreSQL",
                    "finding": "Encryption at rest is enabled."
                })
            else:
                self.findings.append({
                    "status": "FAIL",
                    "component": "Database: PostgreSQL",
                    "finding": "Encryption at rest is DISABLED. Volume encryption required for PHI."
                })

        # Check MongoDB
        if "mongodb" in configs:
            mongo_config = configs["mongodb"]
            if mongo_config.get("encryption_at_rest"):
                self.findings.append({
                    "status": "PASS",
                    "component": "Database: MongoDB",
                    "finding": "Encryption at rest is enabled."
                })
            else:
                self.findings.append({
                    "status": "FAIL",
                    "component": "Database: MongoDB",
                    "finding": "Encryption at rest is DISABLED. Volume encryption required for PHI."
                })

        return self.findings

if __name__ == "__main__":
    auditor = DataAtRestAuditor("../mock_data/db_configs.json")
    print(auditor.run_audit())
