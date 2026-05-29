"""Ingest `npm audit --json` results into the finding schema.

EMR front-ends are Node; vulnerable JS dependencies are a HIPAA risk-management
gap (§164.308(a)(1)(ii)(B)). Supports npm v7+ ("vulnerabilities") and v6
("advisories") JSON, from a file or a live `npm audit` run (graceful if npm or
node_modules are absent).
"""
import json
import os
import subprocess

from hipaa_refs import ERROR, FAIL, PASS, WARN, make_finding

_SEV_STATUS = {"critical": FAIL, "high": FAIL, "moderate": WARN, "low": WARN, "info": WARN}
_SEV_NORM = {"critical": "critical", "high": "high", "moderate": "medium",
             "low": "low", "info": "info"}


def normalize_npm_audit(data):
    """Pure: npm audit JSON -> list of findings."""
    findings = []
    if not isinstance(data, dict):
        return [make_finding(ERROR, "npm audit", "Unrecognized audit JSON.", "config_error")]

    vulns = data.get("vulnerabilities")
    if isinstance(vulns, dict) and vulns and "severity" in next(iter(vulns.values()), {}):
        # npm v7+ format
        for name, v in vulns.items():
            sev = str(v.get("severity", "moderate")).lower()
            rng = v.get("range", "")
            findings.append(make_finding(
                _SEV_STATUS.get(sev, WARN), f"npm/{name}",
                f"{sev.upper()} vulnerability in '{name}' ({rng}). Update to a fixed version.",
                "risk_management", severity=_SEV_NORM.get(sev, "medium")))
    elif isinstance(data.get("advisories"), dict):
        # npm v6 format
        for _, adv in data["advisories"].items():
            sev = str(adv.get("severity", "moderate")).lower()
            mod = adv.get("module_name", "?")
            findings.append(make_finding(
                _SEV_STATUS.get(sev, WARN), f"npm/{mod}",
                f"{sev.upper()}: {adv.get('title', 'vulnerability')} in '{mod}'.",
                "risk_management", severity=_SEV_NORM.get(sev, "medium")))

    if not findings:
        findings.append(make_finding(
            PASS, "npm audit", "No known vulnerable npm dependencies reported.",
            "risk_management"))
    return findings


def ingest_npm_audit_file(path):
    if not os.path.exists(path):
        return [make_finding(ERROR, "npm audit", f"File not found: {path}", "config_error")]
    with open(path) as f:
        return normalize_npm_audit(json.load(f))


class NpmAuditAuditor:
    def __init__(self, project_dir=None, results_file=None):
        self.project_dir = project_dir
        self.results_file = results_file
        self.findings = []

    def run_audit(self):
        if self.results_file:
            self.findings = ingest_npm_audit_file(self.results_file)
            return self.findings
        from shutil import which
        if not self.project_dir or which("npm") is None:
            self.findings = [make_finding(
                WARN, "npm audit",
                "No results file and npm/project unavailable; skipping.", "config_error")]
            return self.findings
        try:
            proc = subprocess.run(  # noqa: S603
                ["npm", "audit", "--json"], cwd=self.project_dir,
                capture_output=True, text=True, timeout=300)
            self.findings = normalize_npm_audit(json.loads(proc.stdout or "{}"))
        except Exception as exc:  # noqa: BLE001
            self.findings = [make_finding(ERROR, "npm audit", f"Run failed: {exc}", "config_error")]
        return self.findings
