"""Google Cloud Storage bucket auditor for PHI-relevant controls.

Checks public exposure, uniform bucket-level access, public access prevention,
object versioning (integrity), retention policy (6-year documentation
retention), and default CMEK. The google-cloud-storage client is imported
lazily; the evaluation logic is pure and unit-tested.
"""
from hipaa_refs import ERROR, FAIL, PASS, WARN, make_finding

_SIX_YEARS_SECONDS = 6 * 365 * 24 * 3600


def evaluate_bucket(meta):
    """Pure: a bucket metadata dict -> list of findings.

    Expected keys (all optional): name, public, uniform_bucket_level_access,
    public_access_prevention, versioning_enabled, retention_period_seconds,
    default_kms_key.
    """
    name = meta.get("name", "bucket")
    label = f"GCS Bucket: {name}"
    findings = []

    if meta.get("public"):
        findings.append(make_finding(
            FAIL, label, "Bucket grants access to allUsers/allAuthenticatedUsers (public). "
            "PHI buckets must not be public.", "access_control", severity="critical"))
    else:
        findings.append(make_finding(
            PASS, label, "No public (allUsers) IAM members.", "access_control"))

    if meta.get("public_access_prevention") == "enforced":
        findings.append(make_finding(
            PASS, label, "Public access prevention is enforced.", "access_control"))
    else:
        findings.append(make_finding(
            WARN, label, "Public access prevention is not enforced.", "access_control"))

    if meta.get("uniform_bucket_level_access"):
        findings.append(make_finding(
            PASS, label, "Uniform bucket-level access enabled (no legacy ACLs).", "access_control"))
    else:
        findings.append(make_finding(
            WARN, label, "Uniform bucket-level access disabled; legacy ACLs may grant access.",
            "access_control"))

    if meta.get("versioning_enabled"):
        findings.append(make_finding(
            PASS, label, "Object versioning enabled (supports integrity/recovery).", "integrity"))
    else:
        findings.append(make_finding(
            WARN, label, "Object versioning disabled; enable to protect against alteration/deletion.",
            "integrity"))

    retention = meta.get("retention_period_seconds")
    if retention is None:
        findings.append(make_finding(
            WARN, label, "No retention policy set; HIPAA requires 6-year documentation retention.",
            "documentation_retention"))
    elif retention >= _SIX_YEARS_SECONDS:
        findings.append(make_finding(
            PASS, label, "Retention policy meets the 6-year requirement.",
            "documentation_retention"))
    else:
        findings.append(make_finding(
            FAIL, label, f"Retention policy ({int(retention/86400)} days) is under 6 years.",
            "documentation_retention"))

    if meta.get("default_kms_key"):
        findings.append(make_finding(
            PASS, label, "Default CMEK configured for objects at rest.", "encryption_at_rest"))
    else:
        findings.append(make_finding(
            WARN, label, "No default CMEK; objects use Google-managed keys "
            "(acceptable, but confirm against your risk analysis).", "encryption_at_rest"))
    return findings


class GCSAuditor:
    def __init__(self, project_id=None, buckets=None):
        self.project_id = project_id
        self.buckets = buckets  # optional explicit list of names
        self.findings = []

    def run_audit(self):
        try:
            from google.cloud import storage  # lazy
        except ImportError:
            self.findings.append(make_finding(
                ERROR, "GCS Auditor",
                "google-cloud-storage not installed; cannot run GCS check.", "config_error"))
            return self.findings
        try:
            client = storage.Client(project=self.project_id)
            names = self.buckets or [b.name for b in client.list_buckets()]
            for bname in names:
                b = client.get_bucket(bname)
                policy = b.get_iam_policy(requested_policy_version=3)
                members = set()
                for binding in policy.bindings:
                    members |= set(binding.get("members", []))
                meta = {
                    "name": b.name,
                    "public": bool(members & {"allUsers", "allAuthenticatedUsers"}),
                    "uniform_bucket_level_access": b.iam_configuration.uniform_bucket_level_access_enabled,
                    "public_access_prevention": b.iam_configuration.public_access_prevention,
                    "versioning_enabled": b.versioning_enabled,
                    "retention_period_seconds": b.retention_period,
                    "default_kms_key": b.default_kms_key_name,
                }
                self.findings.extend(evaluate_bucket(meta))
        except Exception as exc:  # noqa: BLE001
            self.findings.append(make_finding(
                ERROR, "GCS Auditor", f"Failed to audit buckets: {exc}", "config_error"))
        return self.findings
