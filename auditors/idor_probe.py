"""Authenticated authorization / IDOR probe (DAST).

Drives the target API as one principal (the "attacker", e.g. patient A) and
attempts to read another principal's resource (the "victim", e.g. patient B).
A 200 that contains the victim's data is a cross-tenant access-control failure
(broken object-level authorization / RLS bypass) — the EMR's top HIPAA risk.

Config-driven so it stays target-agnostic. Tokens/cookies are supplied by the
operator (never stored). Evaluation is pure and unit-tested.
"""
import json
import os
import ssl
import urllib.error
import urllib.request

from hipaa_refs import ERROR, FAIL, PASS, WARN, make_finding

_DENY_CODES = {401, 403, 404}


def evaluate_idor_response(status_code, body, victim_marker=None):
    """Pure: classify a probe response. Returns (status, message)."""
    if status_code in _DENY_CODES:
        return PASS, f"Access correctly denied (HTTP {status_code})."
    if status_code == 200:
        if victim_marker and victim_marker in (body or ""):
            return FAIL, ("Cross-tenant data exposed: attacker principal read the victim "
                          f"resource (HTTP 200, contains '{victim_marker}').")
        return WARN, ("HTTP 200 to a cross-tenant request; no victim marker matched — "
                      "verify the response is empty/filtered, not a silent leak.")
    return WARN, f"Unexpected response (HTTP {status_code}); review manually."


class IDORAuditor:
    def __init__(self, config_path=None, config=None, allow_private=False):
        self.config_path = config_path
        self.config = config
        self.allow_private = allow_private
        self.findings = []

    def _load(self):
        if self.config is not None:
            return self.config
        if not self.config_path or not os.path.exists(self.config_path):
            return None
        with open(self.config_path) as f:
            return json.load(f)

    def _request(self, method, url, headers):
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        req = urllib.request.Request(url, method=method, headers=headers or {})  # noqa: S310
        try:
            with urllib.request.urlopen(req, timeout=10, context=ctx) as resp:  # noqa: S310
                return resp.getcode(), resp.read(65536).decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            return e.code, ""
        except Exception as exc:  # noqa: BLE001
            return None, str(exc)

    def run_audit(self):
        cfg = self._load()
        if not cfg:
            self.findings.append(make_finding(
                ERROR, "IDOR Probe", "No probe config provided.", "config_error"))
            return self.findings
        base = cfg.get("base_url", "").rstrip("/")
        if not self.allow_private and base:
            try:
                from security import validate_target_url
                validate_target_url(base)
            except Exception as exc:  # noqa: BLE001
                self.findings.append(make_finding(
                    ERROR, "IDOR Probe", f"Target rejected by safety check: {exc}",
                    "access_control"))
                return self.findings
        for probe in cfg.get("probes", []):
            name = probe.get("name", "probe")
            path = probe.get("path", "").replace("{victim_id}", probe.get("victim_id", ""))
            url = base + path if path.startswith("/") else path
            code, body = self._request(probe.get("method", "GET"), url, probe.get("headers"))
            if code is None:
                self.findings.append(make_finding(
                    ERROR, f"IDOR: {name}", f"Request failed: {body}", "access_control"))
                continue
            status, msg = evaluate_idor_response(code, body, probe.get("victim_marker"))
            sev = "critical" if status == FAIL else None
            self.findings.append(make_finding(status, f"IDOR: {name}", msg,
                                               "access_control", severity=sev))
        return self.findings


if __name__ == "__main__":
    import sys
    print(IDORAuditor(config_path=sys.argv[1] if len(sys.argv) > 1 else None).run_audit())
