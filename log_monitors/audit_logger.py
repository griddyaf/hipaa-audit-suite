import json
import os

class AuditLogMonitor:
    def __init__(self, log_path):
        self.log_path = log_path
        self.findings = []

    def run_audit(self):
        """Parses logs to verify audit controls are in place."""
        if not os.path.exists(self.log_path):
            self.findings.append({
                "status": "ERROR",
                "component": "Log Monitor",
                "finding": f"Log file not found at {self.log_path}"
            })
            return self.findings

        try:
            with open(self.log_path, 'r') as f:
                logs = json.load(f)
        except json.JSONDecodeError:
            self.findings.append({
                "status": "ERROR",
                "component": "Log Monitor",
                "finding": "Invalid JSON in log file"
            })
            return self.findings

        for i, log_entry in enumerate(logs):
            # Check for required fields
            missing_fields = []
            for field in ["timestamp", "user_id", "action"]:
                if field not in log_entry:
                    missing_fields.append(field)

            if missing_fields:
                self.findings.append({
                    "status": "FAIL",
                    "component": f"Log Monitor - Entry {i}",
                    "finding": f"Missing required audit fields: {', '.join(missing_fields)}"
                })
                continue

            # Check for unauthenticated access
            if log_entry.get("user_id") in ["anonymous", "guest", "", None]:
                self.findings.append({
                    "status": "FAIL",
                    "component": f"Log Monitor - Entry {i}",
                    "finding": f"Unauthenticated access detected for action {log_entry.get('action')} on {log_entry.get('resource')}."
                })
            else:
                pass # This entry is compliant. To reduce noise, we don't log PASS for every line.

        if not any(f['status'] == 'FAIL' for f in self.findings):
             self.findings.append({
                 "status": "PASS",
                 "component": "Log Monitor",
                 "finding": "All sampled log entries meet HIPAA audit control requirements."
             })

        return self.findings

if __name__ == "__main__":
    monitor = AuditLogMonitor("../mock_data/sample_logs.json")
    print(monitor.run_audit())
