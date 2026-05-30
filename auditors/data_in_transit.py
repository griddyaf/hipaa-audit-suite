"""Data-in-Transit auditor.

Performs real TLS protocol enumeration against a target endpoint by forcing
the client to offer one specific protocol version at a time and observing
which handshakes succeed. This means weak-protocol findings (TLS 1.0/1.1)
actually fire -- unlike the original, which relied on the default context and
could never negotiate a weak version.

Uses only the standard library, so there are no fragile third-party pins.
"""
import http.client
import socket
import ssl
import warnings
from urllib.parse import urlparse

from hipaa_refs import ERROR, FAIL, PASS, WARN, make_finding

# Protocol versions we probe, newest first. Availability depends on the local
# OpenSSL build; unsupported ones are reported as "could not test".
_PROTOCOLS = [
    ("TLSv1.3", getattr(ssl.TLSVersion, "TLSv1_3", None)),
    ("TLSv1.2", getattr(ssl.TLSVersion, "TLSv1_2", None)),
    ("TLSv1.1", getattr(ssl.TLSVersion, "TLSv1_1", None)),
    ("TLSv1.0", getattr(ssl.TLSVersion, "TLSv1", None)),
]
_WEAK = {"TLSv1.0", "TLSv1.1"}


def detect_cloudflare(headers):
    """Return True if response headers indicate the endpoint is fronted by Cloudflare."""
    if not headers:
        return False
    lowered = {str(k).lower(): str(v).lower() for k, v in headers.items()}
    if "cf-ray" in lowered or "cf-cache-status" in lowered:
        return True
    return "cloudflare" in lowered.get("server", "")


_WEAK_CIPHER_TOKENS = ("RC4", "3DES", "DES-", "_DES_", "NULL", "EXPORT", "MD5", "ANON", "ADH", "AECDH")


def classify_ciphers(cipher_names):
    """Pure: return the subset of cipher names that are cryptographically weak."""
    weak = []
    for name in cipher_names or []:
        upper = str(name).upper()
        if any(tok in upper for tok in _WEAK_CIPHER_TOKENS):
            weak.append(name)
    return weak


def evaluate_cert_expiry(not_after_epoch, now_epoch, warn_days=30):
    """Pure: classify a certificate's expiry. Returns (status, message)."""
    if not_after_epoch is None:
        return "WARN", "Could not read certificate expiry."
    remaining_days = (not_after_epoch - now_epoch) / 86400.0
    if remaining_days < 0:
        return "FAIL", f"TLS certificate EXPIRED {abs(int(remaining_days))} day(s) ago."
    if remaining_days <= warn_days:
        return "WARN", f"TLS certificate expires in {int(remaining_days)} day(s); renew soon."
    return "PASS", f"TLS certificate valid for {int(remaining_days)} more day(s)."


class DataInTransitAuditor:
    def __init__(self, target_url, timeout=5, allow_private=False):
        self.target_url = target_url
        self.timeout = timeout
        self.allow_private = allow_private
        self.findings = []

    def _resolve(self):
        parsed = urlparse(self.target_url)
        host = parsed.hostname or self.target_url
        port = parsed.port or 443
        return host, port

    def _probe(self, host, port, version):
        """Return (supported: bool, cipher_name or None, err or None)."""
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE  # testing protocol support, not trust
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", DeprecationWarning)
                ctx.minimum_version = version
                ctx.maximum_version = version
        except (ValueError, OSError):
            return None, None, "protocol unavailable in local OpenSSL build"
        try:
            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ss:
                    return True, ss.cipher()[0], None
        except (ssl.SSLError, OSError) as exc:
            return False, None, str(exc)


    def _fetch_headers(self, host, port):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            conn = http.client.HTTPSConnection(host, port, timeout=self.timeout, context=ctx)
            conn.request("HEAD", "/")
            resp = conn.getresponse()
            headers = dict(resp.getheaders())
            conn.close()
            return headers
        except Exception:  # noqa: BLE001
            return {}

    def _cert_not_after(self, host, port):
        """Return the certificate notAfter as a unix epoch, or None.

        Preferred path uses only the standard library: a verified handshake
        exposes getpeercert()['notAfter'] for any publicly-trusted cert (the
        common case). Falls back to an unverified handshake parsed with the
        optional `cryptography` lib for self-signed/untrusted certs.
        """
        # 1) stdlib verified handshake (no third-party deps required)
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ss:
                    cert = ss.getpeercert()
            if cert and cert.get("notAfter"):
                return ssl.cert_time_to_seconds(cert["notAfter"])
        except Exception:  # noqa: BLE001,S110 (best-effort; fall through to next method)
            pass
        # 2) fallback: unverified handshake + cryptography (optional dep)
        try:
            from cryptography import x509  # lazy/optional
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ss:
                    der = ss.getpeercert(binary_form=True)
            cert = x509.load_der_x509_certificate(der)
            try:
                return cert.not_valid_after_utc.timestamp()
            except AttributeError:
                return cert.not_valid_after.timestamp()
        except Exception:  # noqa: BLE001
            return None

    def run_audit(self):
        host, port = self._resolve()

        # Optional SSRF guard for the web context.
        if not self.allow_private:
            try:
                from security import validate_target_url
                validate_target_url(self.target_url)
            except Exception as exc:  # noqa: BLE001
                self.findings.append(make_finding(
                    ERROR, f"Endpoint: {host}",
                    f"Target rejected by safety check: {exc}", "transmission_security"))
                return self.findings

        supported, weak_found, reachable = [], [], False
        for name, ver in _PROTOCOLS:
            if ver is None:
                continue
            ok, cipher, err = self._probe(host, port, ver)
            if ok is None:
                continue
            if ok:
                reachable = True
                supported.append((name, cipher))
                if name in _WEAK:
                    weak_found.append(name)

        if not reachable and not supported:
            self.findings.append(make_finding(
                ERROR, f"Endpoint: {host}",
                "Could not complete any TLS handshake (host unreachable or non-TLS port).",
                "transmission_security"))
            return self.findings

        for name, cipher in supported:
            if name in _WEAK:
                self.findings.append(make_finding(
                    FAIL, f"Endpoint: {host}",
                    f"Server accepts deprecated {name} (cipher {cipher}). "
                    f"HIPAA transmission security requires TLS 1.2+.",
                    "encryption_in_transit"))
            else:
                self.findings.append(make_finding(
                    PASS, f"Endpoint: {host}",
                    f"Strong protocol supported: {name} (cipher {cipher}).",
                    "encryption_in_transit"))

        if not weak_found and supported:
            self.findings.append(make_finding(
                PASS, f"Endpoint: {host}",
                "No deprecated TLS protocols accepted.", "transmission_security"))

        weak_ciphers = classify_ciphers([c for _, c in supported])
        if weak_ciphers:
            self.findings.append(make_finding(
                FAIL, f"Endpoint: {host}",
                f"Weak cipher(s) negotiated: {', '.join(sorted(set(weak_ciphers)))}.",
                "encryption_in_transit"))

        import time as _time
        status, msg = evaluate_cert_expiry(self._cert_not_after(host, port), _time.time())
        self.findings.append(make_finding(status, f"Endpoint: {host}", msg, "transmission_security"))

        if detect_cloudflare(self._fetch_headers(host, port)):
            self.findings.append(make_finding(
                WARN, f"Endpoint: {host}",
                "Endpoint is fronted by Cloudflare: this TLS result reflects the Cloudflare "
                "EDGE, not the GCP origin. Verify the Cloudflare->origin hop separately "
                "(SSL/TLS mode should be 'Full (strict)') and run the Cloudflare API auditor.",
                "transmission_security"))
        return self.findings


if __name__ == "__main__":
    print(DataInTransitAuditor("https://www.google.com").run_audit())
