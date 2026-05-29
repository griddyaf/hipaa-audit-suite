"""Centralized HIPAA Security Rule citations and a finding factory.

Each auditor references these so the generated report can cite the exact
provision of 45 CFR Part 164 (Subpart C, the Security Rule) that a finding
relates to. Citations are paraphrased pointers, not legal advice.
"""

# Map of short keys -> (CFR citation, plain-language safeguard name)
CITATIONS = {
    "encryption_at_rest": (
        "45 CFR §164.312(a)(2)(iv)",
        "Encryption and Decryption (addressable) – access control standard",
    ),
    "encryption_in_transit": (
        "45 CFR §164.312(e)(2)(ii)",
        "Encryption (addressable) – transmission security standard",
    ),
    "transmission_security": (
        "45 CFR §164.312(e)(1)",
        "Transmission Security – guard against unauthorized access to ePHI in transit",
    ),
    "audit_controls": (
        "45 CFR §164.312(b)",
        "Audit Controls – record and examine activity in systems with ePHI",
    ),
    "access_control": (
        "45 CFR §164.312(a)(1)",
        "Access Control – allow access only to authorized persons/software",
    ),
    "unique_user_id": (
        "45 CFR §164.312(a)(2)(i)",
        "Unique User Identification (required) – assign a unique name/number per user",
    ),
    "least_privilege": (
        "45 CFR §164.308(a)(4)",
        "Information Access Management – authorize access consistent with minimum necessary",
    ),
    "integrity": (
        "45 CFR §164.312(c)(1)",
        "Integrity – protect ePHI from improper alteration or destruction",
    ),
    "automatic_logoff": (
        "45 CFR §164.312(a)(2)(iii)",
        "Automatic Logoff (addressable) – terminate sessions after inactivity",
    ),
    "contingency_backup": (
        "45 CFR §164.308(a)(7)(ii)(A)",
        "Data Backup Plan (required) – retrievable exact copies of ePHI",
    ),
    "documentation_retention": (
        "45 CFR §164.316(b)(2)(i)",
        "Retention – retain required documentation for six years",
    ),
    "config_error": (
        "45 CFR §164.308(a)(1)(ii)(A)",
        "Risk Analysis – unable to assess; remediate data/access gap",
    ),
}

# Valid statuses
PASS = "PASS"  # noqa: S105 (status label, not a secret)
FAIL = "FAIL"
WARN = "WARN"
ERROR = "ERROR"


def make_finding(status, component, finding, citation_key=None, severity=None):
    """Build a finding dict with an optional HIPAA citation attached."""
    citation, safeguard = ("", "")
    if citation_key and citation_key in CITATIONS:
        citation, safeguard = CITATIONS[citation_key]
    return {
        "status": status,
        "component": component,
        "finding": finding,
        "citation": citation,
        "safeguard": safeguard,
        "severity": severity or _default_severity(status),
    }


def _default_severity(status):
    return {
        PASS: "info",
        WARN: "medium",
        FAIL: "high",
        ERROR: "medium",
    }.get(status, "medium")
