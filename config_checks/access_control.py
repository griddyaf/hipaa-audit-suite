"""Access-Control / least-privilege auditor.

Two modes:
  * file – evaluate a local JSON of role->permissions (offline demo).
  * gcp  – pull the live IAM allow-policy for a GCP project via the Resource
           Manager API and flag least-privilege / public-access violations.

The google-cloud client is imported lazily so file mode needs no GCP deps.
"""
import json
import os

from hipaa_refs import ERROR, FAIL, PASS, make_finding

# Basic/primitive GCP roles that grant broad, non-minimal access.
_BROAD_GCP_ROLES = {"roles/owner", "roles/editor"}
# Members that expose resources publicly.
_PUBLIC_MEMBERS = {"allUsers", "allAuthenticatedUsers"}
# File-mode: permissions a non-admin role should not hold.
_RESTRICTED_PERMS = {"manage_users", "delete_all", "write_all"}


class AccessControlAuditor:
    def __init__(self, iam_path="mock_data/sample_iam.json", mode="file", project_id=None):
        self.iam_path = iam_path
        self.mode = mode
        self.project_id = project_id
        self.findings = []

    def run_audit(self):
        if self.mode == "gcp":
            return self._run_gcp()
        return self._run_file()

    # ----------------------------- file ------------------------------- #
    def _run_file(self):
        if not os.path.exists(self.iam_path):
            self.findings.append(make_finding(
                ERROR, "Access Control Auditor",
                f"IAM config file not found at {self.iam_path}", "config_error"))
            return self.findings
        try:
            with open(self.iam_path) as f:
                iam_config = json.load(f)
        except json.JSONDecodeError:
            self.findings.append(make_finding(
                ERROR, "Access Control Auditor",
                "Invalid JSON in IAM config file", "config_error"))
            return self.findings

        for role, data in iam_config.get("roles", {}).items():
            if role == "admin":
                continue
            perms = data.get("permissions", [])
            violations = sorted(set(perms) & _RESTRICTED_PERMS)
            if violations:
                self.findings.append(make_finding(
                    FAIL, f"IAM Role: {role}",
                    f"Violates least privilege. Holds restricted permissions: {', '.join(violations)}.",
                    "least_privilege"))
            else:
                self.findings.append(make_finding(
                    PASS, f"IAM Role: {role}",
                    "Role adheres to least-privilege baseline.", "least_privilege"))
        return self.findings

    # ------------------------------ gcp ------------------------------- #
    def _run_gcp(self):
        if not self.project_id:
            self.findings.append(make_finding(
                ERROR, "GCP IAM Auditor", "No project_id provided for GCP mode.", "config_error"))
            return self.findings
        try:
            from google.cloud import resourcemanager_v3  # lazy
            from google.iam.v1 import iam_policy_pb2
        except ImportError:
            self.findings.append(make_finding(
                ERROR, "GCP IAM Auditor",
                "google-cloud-resource-manager not installed; cannot run GCP check.",
                "config_error"))
            return self.findings
        try:
            client = resourcemanager_v3.ProjectsClient()
            request = iam_policy_pb2.GetIamPolicyRequest(
                resource=f"projects/{self.project_id}")
            policy = client.get_iam_policy(request=request)
        except Exception as exc:  # noqa: BLE001
            self.findings.append(make_finding(
                ERROR, "GCP IAM Auditor",
                f"Failed to fetch IAM policy: {exc}", "config_error"))
            return self.findings

        self._evaluate_bindings(policy.bindings)
        return self.findings

    def _evaluate_bindings(self, bindings):
        """Evaluate proto-or-dict bindings; flag broad roles and public members."""
        any_issue = False
        for b in bindings:
            role = getattr(b, "role", None) or (b.get("role") if isinstance(b, dict) else None)
            members = list(getattr(b, "members", None) or
                           (b.get("members") if isinstance(b, dict) else []) or [])

            public = sorted(m for m in members if m.split(":")[0] in _PUBLIC_MEMBERS
                            or m in _PUBLIC_MEMBERS)
            if public:
                any_issue = True
                self.findings.append(make_finding(
                    FAIL, f"GCP Binding: {role}",
                    f"Public/anonymous access granted to {role} for: {', '.join(public)}. "
                    "PHI resources must not be exposed publicly.",
                    "access_control"))

            if role in _BROAD_GCP_ROLES:
                any_issue = True
                user_members = [m for m in members if m not in public]
                self.findings.append(make_finding(
                    FAIL, f"GCP Binding: {role}",
                    f"Primitive role {role} grants broad access to {len(user_members)} member(s): "
                    f"{', '.join(user_members) or 'n/a'}. Use predefined/custom roles (minimum necessary).",
                    "least_privilege"))

        if not any_issue:
            self.findings.append(make_finding(
                PASS, "GCP IAM Auditor",
                "No primitive-role or public-access least-privilege violations found.",
                "least_privilege"))


if __name__ == "__main__":
    print(AccessControlAuditor("../mock_data/sample_iam.json").run_audit())
