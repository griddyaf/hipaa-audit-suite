"""Audit-controls log monitor.

Ingests real log formats and verifies HIPAA audit-control requirements:
each access to ePHI must be attributable to a unique user and time-stamped.

Supported formats (auto-detected):
  * json    – a JSON array of event objects (original demo format).
  * jsonl   – newline-delimited JSON objects.
  * cloudtrail – AWS CloudTrail export ({"Records": [...]}); normalized.
  * syslog  – RFC3164-ish text lines; best-effort field extraction.
"""
import json
import os
import re

from hipaa_refs import ERROR, FAIL, PASS, WARN, make_finding

_REQUIRED = ("timestamp", "user_id", "action")
_ANON = {"anonymous", "guest", "", None}
_SYSLOG_RE = re.compile(
    r"^(?P<timestamp>\w{3}\s+\d+\s[\d:]+)\s+\S+\s+(?P<action>\w+).*?"
    r"(user|uid)=(?P<user_id>\S+)", re.IGNORECASE)


class AuditLogMonitor:
    def __init__(self, log_path="mock_data/sample_logs.json", fmt="auto"):
        self.log_path = log_path
        self.fmt = fmt
        self.findings = []

    # ------------------------------------------------------------------ #
    def run_audit(self):
        if not os.path.exists(self.log_path):
            self.findings.append(make_finding(
                ERROR, "Log Monitor", f"Log file not found at {self.log_path}", "config_error"))
            return self.findings
        try:
            events = self._load_events()
        except ValueError as exc:
            self.findings.append(make_finding(
                ERROR, "Log Monitor", str(exc), "config_error"))
            return self.findings

        if not events:
            self.findings.append(make_finding(
                WARN, "Log Monitor", "No log entries parsed from file.", "audit_controls"))
            return self.findings

        had_fail = False
        for i, entry in enumerate(events):
            missing = [f for f in _REQUIRED if not entry.get(f)]
            if missing:
                had_fail = True
                self.findings.append(make_finding(
                    FAIL, f"Log Monitor - Entry {i}",
                    f"Missing required audit fields: {', '.join(missing)}.",
                    "audit_controls"))
                continue
            if entry.get("user_id") in _ANON:
                had_fail = True
                self.findings.append(make_finding(
                    FAIL, f"Log Monitor - Entry {i}",
                    f"Unauthenticated/anonymous access to "
                    f"{entry.get('resource', 'unknown resource')} (action {entry.get('action')}).",
                    "unique_user_id"))

        if not had_fail:
            self.findings.append(make_finding(
                PASS, "Log Monitor",
                f"All {len(events)} parsed entries meet audit-control requirements.",
                "audit_controls"))
        return self.findings

    # ------------------------------ load ------------------------------ #
    def _detect_fmt(self, text):
        if self.fmt != "auto":
            return self.fmt
        ext = os.path.splitext(self.log_path)[1].lower()
        if ext == ".jsonl":
            return "jsonl"
        if ext in (".log", ".txt"):
            return "syslog"
        stripped = text.lstrip()
        head = stripped[:400]
        if "protoPayload" in head or '"logName"' in head:
            return "gcp_audit"
        if stripped.startswith("{") and '"Records"' in head:
            return "cloudtrail"
        if stripped.startswith("["):
            return "json"
        if stripped.startswith("{"):
            return "jsonl"
        return "syslog"

    def _load_events(self):
        with open(self.log_path) as f:
            text = f.read()
        fmt = self._detect_fmt(text)
        if fmt == "json":
            data = json.loads(text)
            return data if isinstance(data, list) else [data]
        if fmt == "cloudtrail":
            recs = json.loads(text).get("Records", [])
            return [self._normalize_cloudtrail(r) for r in recs]
        if fmt == "gcp_audit":
            return [self._normalize_gcp_audit(e) for e in self._load_gcp_entries(text)]
        if fmt == "jsonl":
            out = []
            for line in text.splitlines():
                line = line.strip()
                if line:
                    out.append(json.loads(line))
            return out
        if fmt == "syslog":
            return [self._parse_syslog(ln) for ln in text.splitlines() if ln.strip()]
        raise ValueError(f"Unsupported log format: {fmt}")

    @staticmethod
    def _normalize_cloudtrail(rec):
        ident = rec.get("userIdentity", {})
        return {
            "timestamp": rec.get("eventTime"),
            "user_id": ident.get("userName") or ident.get("arn") or ident.get("principalId"),
            "action": rec.get("eventName"),
            "resource": rec.get("eventSource"),
        }


    @staticmethod
    def _load_gcp_entries(text):
        text = text.strip()
        if text.startswith("["):
            return json.loads(text)
        obj_or_lines = []
        # support {"entries": [...]} and NDJSON of LogEntry objects
        if text.startswith("{") and '"entries"' in text[:200]:
            return json.loads(text).get("entries", [])
        for line in text.splitlines():
            line = line.strip()
            if line:
                obj_or_lines.append(json.loads(line))
        return obj_or_lines

    @staticmethod
    def _normalize_gcp_audit(entry):
        proto = entry.get("protoPayload", {}) if isinstance(entry, dict) else {}
        auth = proto.get("authenticationInfo", {})
        resource = proto.get("resourceName")
        if not resource:
            res = entry.get("resource", {})
            resource = res.get("type") if isinstance(res, dict) else res
        return {
            "timestamp": entry.get("timestamp") or entry.get("receiveTimestamp"),
            "user_id": auth.get("principalEmail"),
            "action": proto.get("methodName"),
            "resource": resource,
        }

    @staticmethod
    def _parse_syslog(line):
        m = _SYSLOG_RE.search(line)
        if not m:
            return {"raw": line}  # missing fields -> will be flagged
        return m.groupdict()


if __name__ == "__main__":
    print(AuditLogMonitor("../mock_data/sample_logs.json").run_audit())
