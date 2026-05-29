"""Ingest Prowler results into the HIPAA suite's finding schema.

Prowler (https://github.com/prowler-cloud/prowler) already implements deep GCP
checks (Cloud SQL public IP / SSL / CMEK / backups, GCS, KMS, IAM). Rather than
reimplement those, we normalize its output into our findings so everything lands
in one report.

Supports both Prowler v3 native JSON and v4 OCSF JSON. Can ingest an existing
results file or invoke the prowler CLI if it is installed (graceful otherwise).
"""
import glob
import json
import os
import subprocess
import tempfile

from hipaa_refs import ERROR, FAIL, PASS, WARN, make_finding

_STATUS_MAP = {
    "PASS": PASS, "FAIL": FAIL, "MANUAL": WARN, "INFO": WARN,
    "WARNING": WARN, "MUTED": WARN,
}
_SEV_MAP = {
    "critical": "critical", "high": "high", "medium": "medium",
    "low": "low", "informational": "info", "info": "info",
}


def _first(d, *keys, default=None):
    for k in keys:
        if isinstance(d, dict) and d.get(k) not in (None, ""):
            return d[k]
    return default


def _normalize_one(rec):
    # status: v3 "Status"; v4 OCSF "status_code"
    raw_status = str(_first(rec, "Status", "status_code", "status", default="")).upper()
    status = _STATUS_MAP.get(raw_status, WARN)

    title = _first(rec, "CheckTitle", "check_title", default=None)
    if not title:
        title = _first(rec.get("finding_info", {}), "title", default="Prowler check")

    sev_raw = str(_first(rec, "Severity", "severity", default="medium")).lower()
    severity = _SEV_MAP.get(sev_raw, "medium")

    service = _first(rec, "ServiceName", "service_name", default="gcp")
    resource = _first(rec, "ResourceId", "ResourceName", default=None)
    if not resource:
        res = rec.get("resources") or rec.get("Resources") or []
        if res and isinstance(res, list):
            resource = _first(res[0], "name", "uid", default="")

    detail = _first(rec, "StatusExtended", "status_detail", "risk_details", default="") \
        or _first(rec.get("finding_info", {}), "desc", default="")
    finding_text = f"{title}"
    if resource:
        finding_text += f" [resource: {resource}]"
    if detail:
        finding_text += f" — {detail}"

    f = make_finding(status, f"Prowler/{service}", finding_text, severity=severity)
    return f


def normalize_prowler_findings(raw_list):
    """Pure: list of Prowler records -> list of suite findings."""
    out = []
    for rec in raw_list or []:
        try:
            out.append(_normalize_one(rec))
        except Exception:  # noqa: BLE001,S112 - never let one bad record kill the run
            continue
    return out


def ingest_prowler_file(path):
    if not os.path.exists(path):
        return [make_finding(ERROR, "Prowler", f"Results file not found: {path}", "config_error")]
    try:
        with open(path) as f:
            data = json.load(f)
    except json.JSONDecodeError:
        # try NDJSON
        data = []
        with open(path) as f:
            for line in f:
                line = line.strip()
                if line:
                    data.append(json.loads(line))
    if isinstance(data, dict):
        data = data.get("findings") or data.get("Findings") or [data]
    return normalize_prowler_findings(data)


class ProwlerAuditor:
    """Run prowler (if installed) or ingest a pre-generated results file."""

    def __init__(self, provider="gcp", project=None, results_file=None, run=False):
        self.provider = provider
        self.project = project
        self.results_file = results_file
        self.run = run
        self.findings = []

    def run_audit(self):
        if self.results_file:
            self.findings = ingest_prowler_file(self.results_file)
            return self.findings
        if not self.run:
            self.findings = [make_finding(
                WARN, "Prowler",
                "No results file and live run not requested; skipping.", "config_error")]
            return self.findings
        from shutil import which
        if which("prowler") is None:
            self.findings = [make_finding(
                ERROR, "Prowler",
                "prowler CLI not installed (pip install prowler).", "config_error")]
            return self.findings
        outdir = tempfile.mkdtemp(prefix="prowler_")
        cmd = ["prowler", self.provider, "-M", "json-ocsf", "-o", outdir]
        if self.project:
            cmd += ["--project-ids", self.project]
        try:
            subprocess.run(cmd, check=False, capture_output=True, timeout=1800)  # noqa: S603
        except Exception as exc:  # noqa: BLE001
            self.findings = [make_finding(ERROR, "Prowler", f"Run failed: {exc}", "config_error")]
            return self.findings
        files = sorted(glob.glob(os.path.join(outdir, "*.ocsf.json")) +
                       glob.glob(os.path.join(outdir, "*.json")))
        if not files:
            self.findings = [make_finding(ERROR, "Prowler", "No output produced.", "config_error")]
            return self.findings
        self.findings = ingest_prowler_file(files[-1])
        return self.findings
