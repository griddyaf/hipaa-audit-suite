"""Tier-2 application source scanners (SAST).

Heuristic, framework-agnostic static checks for common EMR/web vulnerability
classes that infra auditing can't see. These are *indicators for review*, not
proofs — they intentionally favor surfacing risky patterns. Each scanner is a
pure function over a {path: source_text} map so it is unit-testable.

Covered:
  * SQL injection   – raw interpolation into query() template literals
  * SSRF            – server-side fetch of request-derived URLs w/o allow-list
  * Upload safety   – trusted content-type / unsanitized filename in object keys
  * CSRF coverage   – mutating API routes outside CSRF-protected prefixes
  * MFA posture     – plaintext TOTP secret at rest, missing replay protection
"""
import os
import re

from hipaa_refs import ERROR, FAIL, PASS, WARN, make_finding

_CODE_EXT = (".ts", ".tsx", ".js", ".jsx", ".mjs")
_SKIP_DIRS = {"node_modules", ".git", ".next", "dist", "build", "__pycache__", "coverage"}


def _loc(text, idx):
    return text.count("\n", 0, idx) + 1


def _is_test(path):
    p = path.replace(os.sep, "/").lower()
    return (
        "__tests__" in p
        or "/e2e/" in p
        or "/tests/" in p
        or "/test/" in p
        or ".test." in p
        or ".spec." in p
    )


# --------------------------------------------------------------------------- #
# SQL injection
# --------------------------------------------------------------------------- #
_SQLI = re.compile(r"\b(query|execute)\s*\(\s*`[^`]*\$\{", re.IGNORECASE)


_SQL_DYNAMIC = re.compile(
    r"`[^`]*\b(?:SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM|WHERE|VALUES)\b[^`]*\$\{[^}]+\}[^`]*`",
    re.IGNORECASE)
# An interpolation that is only a placeholder index (e.g. `$${idx}`) is safe.
_SAFE_PLACEHOLDER = re.compile(r"\$\$\{")


def scan_sqli(sources):
    findings = []
    for path, text in sources.items():
        if _is_test(path):
            continue
        for m in _SQLI.finditer(text):
            findings.append(make_finding(
                FAIL, f"SQLi: {os.path.basename(path)}:{_loc(text, m.start())}",
                "String interpolation directly inside a query()/execute() template literal — "
                "use parameterized queries ($1, $2), not `${...}`.", "integrity", severity="high"))
        dyn_lines = []
        for m in _SQL_DYNAMIC.finditer(text):
            frag = m.group(0)
            interps = re.findall(r"(?<!\$)\$\{[^}]+\}", frag)
            # Skip when all interpolations are clearly identifiers/placeholders, not values.
            if interps and all(
                re.search(r"^\$\{\s*(idx|i|n|paramIndex|placeholder|cols|sets|columns|fields|where|order|sort|table)",
                          x, re.IGNORECASE) for x in interps):
                continue
            dyn_lines.append(_loc(text, m.start()))
        if dyn_lines:
            findings.append(make_finding(
                WARN, f"SQLi(dynamic): {os.path.basename(path)}",
                f"{len(dyn_lines)} dynamic-SQL interpolation(s) (lines "
                f"{', '.join(str(x) for x in dyn_lines[:8])}{'…' if len(dyn_lines) > 8 else ''}) — "
                "confirm interpolated parts are fixed identifiers and user values use $1/$2 params.",
                "integrity", severity="medium"))
    return findings


# --------------------------------------------------------------------------- #
# SSRF
# --------------------------------------------------------------------------- #
_FETCH = re.compile(r"\b(?:fetch|axios(?:\.get|\.post)?|got|undici\.request)\s*\(\s*([A-Za-z_$][\w.$]*)")
_SSRF_GUARD = ("allowlist", "allow_list", "isprivate", "is_private", "validateurl", "validate_url",
               "ssrf", "blocklist", "denylist", "resolvedip", "new url(")
_SERVER_HINT = ("/api/", "/lib/", "/server/", "/app/api/")


def _is_server_file(path):
    npath = path.replace(os.sep, "/").lower()
    if npath.endswith((".tsx", ".jsx")):
        return False  # client components
    return any(h in npath for h in _SERVER_HINT)


def scan_ssrf(sources):
    findings = []
    for path, text in sources.items():
        if _is_test(path) or not _is_server_file(path):
            continue
        low = text.lower()
        has_guard = any(g in low for g in _SSRF_GUARD)
        if has_guard:
            continue
        seen = set()
        for m in _FETCH.finditer(text):
            var = m.group(1)
            if var.startswith(("http", "'", '"', "`")) or var in ("input", "url") and False:
                continue
            line = _loc(text, m.start())
            if line in seen:
                continue
            seen.add(line)
            findings.append(make_finding(
                WARN, f"SSRF: {os.path.basename(path)}:{line}",
                f"Server-side fetch of a non-literal URL ('{var}') with no allow-list / "
                "private-IP guard in this file — verify the URL is not attacker-controlled (SSRF).",
                "risk_management", severity="high"))
    return findings


# --------------------------------------------------------------------------- #
# Upload safety
# --------------------------------------------------------------------------- #
_FILENAME_KEY = re.compile(r"`[^`]*\$\{[^}]*(?:filename|file\.name|originalname|fileName)[^}]*\}[^`]*`",
                           re.IGNORECASE)
_CONTENTTYPE_TRUST = re.compile(r"contentType\s*[:=]\s*(?:req|request|body|file|formData|params)\b",
                                re.IGNORECASE)


def scan_upload_safety(sources):
    findings = []
    for path, text in sources.items():
        if _is_test(path):
            continue
        low = text.lower()
        sanitized = "sanitize" in low or "basename(" in low or "slugify" in low
        fn_hit = next(_FILENAME_KEY.finditer(text), None)
        if fn_hit and not sanitized:
            findings.append(make_finding(
                WARN, f"Upload: {os.path.basename(path)}:{_loc(text, fn_hit.start())}",
                "User-supplied filename interpolated into a path/object key without "
                "sanitization — object-key injection / path traversal risk.",
                "integrity", severity="medium"))
        ct_hit = next(_CONTENTTYPE_TRUST.finditer(text), None)
        if ct_hit:
            findings.append(make_finding(
                WARN, f"Upload: {os.path.basename(path)}:{_loc(text, ct_hit.start())}",
                "Declared content-type trusted from the request without magic-byte sniffing.",
                "integrity", severity="medium"))
    return findings


# --------------------------------------------------------------------------- #
# CSRF coverage
# --------------------------------------------------------------------------- #
_MUTATING = re.compile(r"export\s+(?:async\s+)?function\s+(POST|PUT|PATCH|DELETE)\b"
                       r"|export\s+const\s+(POST|PUT|PATCH|DELETE)\s*=")


def scan_csrf_coverage(sources, covered_prefixes=("/api/portal",),
                       marker_tokens=("assertsameorigin", "validateorigin", "csrf", "checkorigin",
                                      "requiresameorigin")):
    """Flag mutating API route handlers not covered by a CSRF origin check.

    A route is considered covered if its path matches a covered prefix OR the
    file references a known origin-check marker.
    """
    findings = []
    for path, text in sources.items():
        if _is_test(path):
            continue
        npath = path.replace(os.sep, "/").lower()
        if "/api/" not in npath:
            continue
        muts = [g for tup in _MUTATING.findall(text) for g in (tup if isinstance(tup, tuple) else (tup,)) if g]
        if not muts:
            continue
        covered = any(pref.lower() in npath for pref in covered_prefixes) \
            or any(tok in text.lower() for tok in marker_tokens)
        if not covered:
            findings.append(make_finding(
                WARN, f"CSRF: …{npath.split('/api/')[-1][:48]}",
                f"Mutating route ({', '.join(sorted(set(muts)))}) outside CSRF-protected "
                "prefixes and with no origin-check marker — verify CSRF protection.",
                "access_control", severity="medium"))
    return findings


# --------------------------------------------------------------------------- #
# MFA posture
# --------------------------------------------------------------------------- #
_PLAINTEXT_MFA = re.compile(r"mfa_secret\s+(?:VARCHAR|TEXT|CHAR)", re.IGNORECASE)


def scan_mfa_posture(sources):
    findings = []
    saw_totp = False
    saw_replay = False
    saw_mfa = False
    for path, text in sources.items():
        low = text.lower()
        if "mfa" in low or "totp" in low:
            saw_mfa = True
        for m in _PLAINTEXT_MFA.finditer(text):
            findings.append(make_finding(
                FAIL, f"MFA: {os.path.basename(path)}:{_loc(text, m.start())}",
                "TOTP `mfa_secret` declared as plaintext column — a single DB read defeats MFA. "
                "Encrypt at rest (e.g. envelope encryption with a KMS/Secret Manager key).",
                "access_control", severity="high"))
        if "verifytotp" in low or "totp.verify" in low or "verify_totp" in low:
            saw_totp = True
        if "last_used" in low or "used_counter" in low or "replay" in low or "last_used_step" in low:
            saw_replay = True
    if saw_totp and not saw_replay:
        findings.append(make_finding(
            WARN, "MFA: replay protection",
            "TOTP verification found but no last-used-counter / replay guard detected — "
            "a captured code may be reusable within its time window.",
            "access_control", severity="medium"))
    if not saw_mfa:
        findings.append(make_finding(
            WARN, "MFA: posture", "No MFA/TOTP implementation detected in scanned source.",
            "access_control"))
    return findings


# --------------------------------------------------------------------------- #
# Aggregator
# --------------------------------------------------------------------------- #
_SCANNERS = {
    "sqli": scan_sqli,
    "ssrf": scan_ssrf,
    "upload": scan_upload_safety,
    "csrf": scan_csrf_coverage,
    "mfa": scan_mfa_posture,
}


def run_all_sast(sources):
    findings = []
    for fn in _SCANNERS.values():
        findings.extend(fn(sources))
    if not any(f["status"] in (FAIL, WARN) for f in findings):
        findings.append(make_finding(
            PASS, "SAST", "No Tier-2 source-pattern issues detected.", "risk_management"))
    return findings


class SASTScanner:
    def __init__(self, root_dir, max_files=8000):
        self.root_dir = root_dir
        self.max_files = max_files
        self.findings = []

    def _load(self):
        sources, count = {}, 0
        for dirpath, dirnames, filenames in os.walk(self.root_dir):
            dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
            for fn in filenames:
                if fn.endswith(_CODE_EXT) or fn.endswith(".sql"):
                    count += 1
                    if count > self.max_files:
                        return sources
                    fp = os.path.join(dirpath, fn)
                    try:
                        with open(fp, encoding="utf-8", errors="replace") as f:
                            sources[fp] = f.read()
                    except OSError:
                        continue
        return sources

    def run_audit(self):
        if not self.root_dir or not os.path.isdir(self.root_dir):
            self.findings.append(make_finding(
                ERROR, "SAST", f"Source directory not found: {self.root_dir}", "config_error"))
            return self.findings
        self.findings = run_all_sast(self._load())
        return self.findings


if __name__ == "__main__":
    import sys
    print(SASTScanner(sys.argv[1] if len(sys.argv) > 1 else ".").run_audit())
