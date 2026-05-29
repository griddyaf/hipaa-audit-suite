"""Cloudflare zone security auditor.

Because the GCP origin sits behind Cloudflare, the externally observable TLS
posture is Cloudflare's edge. This module checks the Cloudflare zone settings
that actually govern PHI-in-transit protection:

  * SSL/TLS encryption mode  -> must be Full (strict) so edge<->origin is verified
  * Minimum TLS version      -> must be >= 1.2
  * Always Use HTTPS         -> redirect http to https
  * HSTS                     -> Strict-Transport-Security enabled

Uses the Cloudflare API v4 over the standard library (no extra deps). The API
token is read from the CLOUDFLARE_API_TOKEN env var unless passed explicitly.
"""
import json
import os
import urllib.error
import urllib.request

from hipaa_refs import ERROR, FAIL, PASS, WARN, make_finding

_API = "https://api.cloudflare.com/client/v4"
_TLS_RANK = {"1.0": 0, "1.1": 1, "1.2": 2, "1.3": 3}


def evaluate_cloudflare_settings(ssl_mode, min_tls, always_https, hsts_enabled):
    """Pure evaluation of Cloudflare zone settings -> findings (unit-testable)."""
    findings = []
    label = "Cloudflare Zone"

    mode = (ssl_mode or "").lower()
    if mode == "strict":
        findings.append(make_finding(
            PASS, label, "SSL/TLS mode is Full (strict); edge-to-origin is encrypted and validated.",
            "transmission_security"))
    elif mode == "full":
        findings.append(make_finding(
            WARN, label,
            "SSL/TLS mode is Full (not strict): origin certificate is NOT validated. "
            "Use Full (strict) for PHI.", "transmission_security"))
    elif mode in ("flexible", "off"):
        findings.append(make_finding(
            FAIL, label,
            f"SSL/TLS mode is '{mode}': traffic to the GCP origin may be unencrypted. "
            "Set Full (strict).", "encryption_in_transit"))
    else:
        findings.append(make_finding(
            WARN, label, f"Unknown SSL/TLS mode '{ssl_mode}'.", "transmission_security"))

    rank = _TLS_RANK.get(str(min_tls), None)
    if rank is None:
        findings.append(make_finding(
            WARN, label, f"Could not determine minimum TLS version ('{min_tls}').",
            "encryption_in_transit"))
    elif rank >= 2:
        findings.append(make_finding(
            PASS, label, f"Minimum TLS version is {min_tls}.", "encryption_in_transit"))
    else:
        findings.append(make_finding(
            FAIL, label,
            f"Minimum TLS version is {min_tls}; HIPAA requires TLS 1.2+. Raise the floor.",
            "encryption_in_transit"))

    if str(always_https).lower() == "on":
        findings.append(make_finding(
            PASS, label, "Always Use HTTPS is enabled.", "transmission_security"))
    else:
        findings.append(make_finding(
            WARN, label, "Always Use HTTPS is off; plaintext requests are not redirected.",
            "transmission_security"))

    if hsts_enabled:
        findings.append(make_finding(
            PASS, label, "HSTS (Strict-Transport-Security) is enabled.", "transmission_security"))
    else:
        findings.append(make_finding(
            WARN, label, "HSTS is not enabled; enable Strict-Transport-Security.",
            "transmission_security"))
    return findings


class CloudflareAuditor:
    def __init__(self, zone_id, api_token=None):
        self.zone_id = zone_id
        self.api_token = api_token or os.environ.get("CLOUDFLARE_API_TOKEN")
        self.findings = []

    def _get_setting(self, name):
        url = f"{_API}/zones/{self.zone_id}/settings/{name}"
        req = urllib.request.Request(url, headers={  # noqa: S310 (fixed https host)
            "Authorization": f"Bearer {self.api_token}",
            "Content-Type": "application/json",
        })
        with urllib.request.urlopen(req, timeout=10) as resp:  # noqa: S310
            data = json.loads(resp.read().decode())
        if not data.get("success", False):
            raise RuntimeError(data.get("errors") or "Cloudflare API error")
        return data["result"]

    def run_audit(self):
        if not self.zone_id:
            self.findings.append(make_finding(
                ERROR, "Cloudflare Zone", "No zone_id provided.", "config_error"))
            return self.findings
        if not self.api_token:
            self.findings.append(make_finding(
                ERROR, "Cloudflare Zone",
                "No API token (set CLOUDFLARE_API_TOKEN).", "config_error"))
            return self.findings
        try:
            ssl_mode = self._get_setting("ssl").get("value")
            min_tls = self._get_setting("min_tls_version").get("value")
            always_https = self._get_setting("always_use_https").get("value")
            hsts = self._get_setting("security_header").get("value", {})
            hsts_enabled = bool(
                hsts.get("strict_transport_security", {}).get("enabled", False))
        except (urllib.error.URLError, RuntimeError, KeyError, ValueError) as exc:
            self.findings.append(make_finding(
                ERROR, "Cloudflare Zone", f"Failed to read zone settings: {exc}", "config_error"))
            return self.findings

        self.findings.extend(evaluate_cloudflare_settings(
            ssl_mode, min_tls, always_https, hsts_enabled))
        return self.findings


if __name__ == "__main__":
    import sys
    zone = sys.argv[1] if len(sys.argv) > 1 else None
    print(CloudflareAuditor(zone).run_audit())
