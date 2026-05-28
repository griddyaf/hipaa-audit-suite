import json
import os

class AccessControlAuditor:
    def __init__(self, iam_path):
        self.iam_path = iam_path
        self.findings = []

    def run_audit(self):
        """Scans IAM configs to verify Principle of Least Privilege."""
        if not os.path.exists(self.iam_path):
            self.findings.append({
                "status": "ERROR",
                "component": "Access Control Auditor",
                "finding": f"IAM config file not found at {self.iam_path}"
            })
            return self.findings

        try:
            with open(self.iam_path, 'r') as f:
                iam_config = json.load(f)
        except json.JSONDecodeError:
            self.findings.append({
                "status": "ERROR",
                "component": "Access Control Auditor",
                "finding": "Invalid JSON in IAM config file"
            })
            return self.findings

        roles = iam_config.get("roles", {})
        
        # Define some least-privilege rules
        # e.g., non-admin roles shouldn't have 'manage_users' or 'write_all'
        restricted_permissions_for_non_admins = ["manage_users", "delete_all", "write_all"]

        for role, data in roles.items():
            if role == "admin":
                continue # Admin is expected to have broad permissions
            
            permissions = data.get("permissions", [])
            violations = [p for p in permissions if p in restricted_permissions_for_non_admins]
            
            if violations:
                self.findings.append({
                    "status": "FAIL",
                    "component": f"IAM Role: {role}",
                    "finding": f"Role violates Least Privilege. Possesses restricted permissions: {', '.join(violations)}."
                })
            else:
                self.findings.append({
                    "status": "PASS",
                    "component": f"IAM Role: {role}",
                    "finding": "Role adheres to Least Privilege baselines."
                })

        return self.findings

if __name__ == "__main__":
    auditor = AccessControlAuditor("../mock_data/sample_iam.json")
    print(auditor.run_audit())
