"""Active HTTP security-header scanner (DAST).

Fetches a URL and grades the response security headers that protect PHI in the
browser: HSTS, CSP (incl. unsafe-inline/eval weaknesses), X-Frame-Options,
X-Content-Type-Options, Referrer-Policy, Permissions-Policy, and PHI cache
control. Evaluation is pure and unit-tested; the fetch uses the stdlib.
"""
import http.client
import ssl
from urllib.parse import urlparse

from hipaa_refs import ERROR, FAIL, PASS, WARN, make_finding


def evaluate_security_headers(headers, is_phi_path=False):
    """Pure: case-insensitive header dict -> list of findings."""
    h = {str(k).lower(): str(v) for k, v in (headers or {}).items()}
    label = "HTTP Security Headers"
    findings = []

    hsts = h.get("strict-transport-security", "")
    if "max-age=" in hsts and not hsts.strip().startswith("max-age=0"):
        findings.append(make_finding(PASS, label, f"HSTS present ({hsts}).", "transmission_security"))
    else:
        findings.append(make_finding(FAIL, label,
            "Missing/!weak Strict-Transport-Security; clients may use plaintext HTTP.",
            "transmission_security"))

    csp = h.get("content-security-policy", "")
    if not csp:
        findings.append(make_finding(FAIL, label,
            "No Content-Security-Policy; XSS mitigation is absent.", "access_control"))
    else:
        if "unsafe-eval" in csp:
            findings.append(make_finding(WARN, label,
                "CSP allows 'unsafe-eval' in script-src (weakens XSS protection).", "access_control"))
        if "unsafe-inline" in csp and "script-src" in csp:
            findings.append(make_finding(WARN, label,
                "CSP script-src allows 'unsafe-inline'; prefer nonces/hashes.", "access_control"))
        if "frame-ancestors" in csp:
            findings.append(make_finding(PASS, label, "CSP sets frame-ancestors.", "access_control"))
        else:
            findings.append(make_finding(WARN, label,
                "CSP missing frame-ancestors directive.", "access_control"))

    xfo = h.get("x-frame-options", "").upper()
    findings.append(make_finding(
        PASS if xfo in ("DENY", "SAMEORIGIN") else WARN, label,
        f"X-Frame-Options: {xfo or 'missing'}.", "access_control"))

    findings.append(make_finding(
        PASS if h.get("x-content-type-options", "").lower() == "nosniff" else WARN, label,
        f"X-Content-Type-Options: {h.get('x-content-type-options', 'missing')}.", "access_control"))

    findings.append(make_finding(
        PASS if h.get("referrer-policy") else WARN, label,
        f"Referrer-Policy: {h.get('referrer-policy', 'missing')}.", "transmission_security"))

    findings.append(make_finding(
        PASS if h.get("permissions-policy") else WARN, label,
        f"Permissions-Policy: {h.get('permissions-policy', 'missing')}.", "access_control"))

    if is_phi_path:
        cache = h.get("cache-control", "").lower()
        if "no-store" in cache or "private" in cache:
            findings.append(make_finding(PASS, label,
                "PHI response is marked no-store/private.", "transmission_security"))
        else:
            findings.append(make_finding(FAIL, label,
                "PHI response lacks Cache-Control: no-store/private (CDN/proxy caching risk).",
                "transmission_security"))
    return findings


class SecurityHeaderAuditor:
    def __init__(self, url, timeout=8, allow_private=False):
        self.url = url
        self.timeout = timeout
        self.allow_private = allow_private
        self.findings = []

    def _fetch(self):
        parsed = urlparse(self.url)
        host = parsed.hostname
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query
        if parsed.scheme == "https":
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            conn = http.client.HTTPSConnection(host, port, timeout=self.timeout, context=ctx)
        else:
            conn = http.client.HTTPConnection(host, port, timeout=self.timeout)
        conn.request("GET", path, headers={"User-Agent": "hipaa-audit-suite"})
        resp = conn.getresponse()
        headers = dict(resp.getheaders())
        conn.close()
        return headers

    def run_audit(self):
        if not self.allow_private:
            try:
                from security import validate_target_url
                validate_target_url(self.url)
            except Exception as exc:  # noqa: BLE001
                self.findings.append(make_finding(
                    ERROR, "HTTP Security Headers",
                    f"Target rejected by safety check: {exc}", "transmission_security"))
                return self.findings
        try:
            headers = self._fetch()
        except Exception as exc:  # noqa: BLE001
            self.findings.append(make_finding(
                ERROR, "HTTP Security Headers", f"Fetch failed: {exc}", "transmission_security"))
            return self.findings
        is_phi = "/api/portal" in (urlparse(self.url).path or "")
        self.findings = evaluate_security_headers(headers, is_phi_path=is_phi)
        return self.findings


if __name__ == "__main__":
    import sys
    print(SecurityHeaderAuditor(sys.argv[1]).run_audit())
