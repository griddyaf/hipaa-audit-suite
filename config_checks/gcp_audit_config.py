"""Verify GCP Data Access audit logging is enabled (HIPAA audit controls).

Parsing logs is useless if the project never records Data Access events. This
checks the project IAM policy's auditConfigs for DATA_READ / DATA_WRITE.
"""
from hipaa_refs import ERROR, FAIL, PASS, make_finding

_REQUIRED_TYPES = {"DATA_READ", "DATA_WRITE"}


def evaluate_audit_config(audit_configs):
    """Pure: list of auditConfig dicts -> findings.

    Each config: {"service": "allServices"|..., "auditLogConfigs": [{"logType": "DATA_READ"}, ...]}
    """
    enabled = set()
    for cfg in audit_configs or []:
        for log_cfg in cfg.get("auditLogConfigs", []):
            lt = log_cfg.get("logType")
            if lt in _REQUIRED_TYPES:
                enabled.add(lt)
    missing = _REQUIRED_TYPES - enabled
    if not missing:
        return [make_finding(
            PASS, "GCP Audit Logging",
            "Data Access audit logging (DATA_READ + DATA_WRITE) is enabled.", "audit_controls")]
    return [make_finding(
        FAIL, "GCP Audit Logging",
        f"Data Access audit logging missing: {', '.join(sorted(missing))}. "
        "Enable so ePHI access is recorded.", "audit_controls")]


class GCPAuditLoggingAuditor:
    def __init__(self, project_id=None):
        self.project_id = project_id
        self.findings = []

    def run_audit(self):
        if not self.project_id:
            self.findings.append(make_finding(
                ERROR, "GCP Audit Logging", "No project_id provided.", "config_error"))
            return self.findings
        try:
            from google.cloud import resourcemanager_v3  # lazy
            from google.iam.v1 import iam_policy_pb2, options_pb2
        except ImportError:
            self.findings.append(make_finding(
                ERROR, "GCP Audit Logging",
                "google-cloud-resource-manager not installed.", "config_error"))
            return self.findings
        try:
            client = resourcemanager_v3.ProjectsClient()
            req = iam_policy_pb2.GetIamPolicyRequest(
                resource=f"projects/{self.project_id}",
                options=options_pb2.GetPolicyOptions(requested_policy_version=3))
            policy = client.get_iam_policy(request=req)
            configs = []
            for ac in getattr(policy, "audit_configs", []):
                configs.append({
                    "service": ac.service,
                    "auditLogConfigs": [{"logType": _LT.get(c.log_type, c.log_type)}
                                        for c in ac.audit_log_configs],
                })
        except Exception as exc:  # noqa: BLE001
            self.findings.append(make_finding(
                ERROR, "GCP Audit Logging", f"Failed to read policy: {exc}", "config_error"))
            return self.findings
        self.findings.extend(evaluate_audit_config(configs))
        return self.findings


# numeric enum -> name fallback
_LT = {1: "ADMIN_READ", 2: "DATA_WRITE", 3: "DATA_READ"}
