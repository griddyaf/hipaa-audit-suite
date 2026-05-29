"""Static check: audit-write reliability (HIPAA audit controls, §164.312(b)).

Flags the pattern where an audit-log write is fired and its failure is silently
swallowed (e.g. `recordAuditEvent(...).catch(() => {})`), which loses the audit
trail with no alert. Pure scanner over source text; framework-agnostic.
"""
import os
import re

from hipaa_refs import ERROR, FAIL, PASS, make_finding

_EMPTY_CATCH = re.compile(r"\.catch\(\s*\(\s*\w*\s*\)\s*=>\s*\{\s*\}\s*\)")
_AUDIT_TOKENS = ("audit", "portal_audit_events", "mfa_audit", "auditevent", "recordaudit")
_CODE_EXT = (".ts", ".tsx", ".js", ".jsx", ".mjs")


def scan_audit_writes(sources):
    """Pure: {path: text} -> findings. Flags swallowed audit-write failures."""
    findings = []
    for path, text in sources.items():
        for m in _EMPTY_CATCH.finditer(text):
            window = text[max(0, m.start() - 220):m.start()].lower()
            if any(tok in window for tok in _AUDIT_TOKENS):
                line = text.count("\n", 0, m.start()) + 1
                findings.append(make_finding(
                    FAIL, f"Audit write: {os.path.basename(path)}:{line}",
                    "Audit-log write failure is silently swallowed (empty .catch); "
                    "audit trail can be lost with no alert. Log/alert on failure.",
                    "audit_controls", severity="high"))
    if not findings:
        findings.append(make_finding(
            PASS, "Audit Write Reliability",
            "No swallowed audit-write failures detected.", "audit_controls"))
    return findings


class AuditWriteScanner:
    def __init__(self, root_dir, max_files=5000):
        self.root_dir = root_dir
        self.max_files = max_files
        self.findings = []

    def run_audit(self):
        if not self.root_dir or not os.path.isdir(self.root_dir):
            self.findings.append(make_finding(
                ERROR, "Audit Write Reliability",
                f"Source directory not found: {self.root_dir}", "config_error"))
            return self.findings
        sources, count = {}, 0
        for dirpath, dirnames, filenames in os.walk(self.root_dir):
            dirnames[:] = [d for d in dirnames if d not in
                           ("node_modules", ".git", ".next", "dist", "build", "__pycache__")]
            for fn in filenames:
                if fn.endswith(_CODE_EXT):
                    count += 1
                    if count > self.max_files:
                        break
                    fp = os.path.join(dirpath, fn)
                    try:
                        with open(fp, encoding="utf-8", errors="replace") as f:
                            sources[fp] = f.read()
                    except OSError:
                        continue
        self.findings = scan_audit_writes(sources)
        return self.findings


if __name__ == "__main__":
    import sys
    print(AuditWriteScanner(sys.argv[1] if len(sys.argv) > 1 else ".").run_audit())
