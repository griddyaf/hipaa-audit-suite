"""Serialize audit findings to machine-readable formats (JSON, SARIF 2.1.0).

SARIF lets findings flow into GitHub code-scanning (Security tab / PR
annotations). JSON is for dashboards and diffing across runs.
"""
import json

_SARIF_LEVEL = {"PASS": "none", "WARN": "warning", "FAIL": "error", "ERROR": "note"}
_SEVERITY_WEIGHT = {"critical": 5, "high": 4, "medium": 2, "low": 1, "info": 0}


def compliance_summary(findings):
    """Return counts + a pass-rate and a severity-weighted risk score (0-100)."""
    counts = {"PASS": 0, "FAIL": 0, "WARN": 0, "ERROR": 0}
    for f in findings:
        counts[f.get("status", "ERROR")] = counts.get(f.get("status", "ERROR"), 0) + 1
    scored = counts["PASS"] + counts["FAIL"]
    pass_rate = round(counts["PASS"] / scored * 100, 1) if scored else None
    # Risk score: weighted open issues (FAIL+WARN), normalized & inverted to 0-100.
    risk_points = sum(
        _SEVERITY_WEIGHT.get(f.get("severity", "medium"), 2)
        for f in findings if f.get("status") in ("FAIL", "WARN"))
    max_points = sum(_SEVERITY_WEIGHT.get("high", 4) for f in findings) or 1
    posture = round(max(0, 100 - (risk_points / max_points * 100)), 1)
    return {
        "total": len(findings),
        "counts": counts,
        "pass_rate": pass_rate,
        "posture_score": posture,
    }


def write_json(findings, path):
    payload = {"summary": compliance_summary(findings), "findings": findings}
    with open(path, "w") as f:
        json.dump(payload, f, indent=2)
    return path


def to_sarif(findings, tool_name="HIPAA Audit Suite", version="1.0.0"):
    rules, rule_index, results = [], {}, []
    for f in findings:
        cite = f.get("citation") or f.get("component", "finding")
        rule_id = cite.replace(" ", "_") or "finding"
        if rule_id not in rule_index:
            rule_index[rule_id] = len(rules)
            rules.append({
                "id": rule_id,
                "name": (f.get("safeguard") or f.get("component", "Finding"))[:120],
                "shortDescription": {"text": f.get("safeguard") or cite},
                "properties": {"citation": f.get("citation", "")},
            })
        results.append({
            "ruleId": rule_id,
            "ruleIndex": rule_index[rule_id],
            "level": _SARIF_LEVEL.get(f.get("status"), "note"),
            "message": {"text": f"[{f.get('status')}] {f.get('component')}: {f.get('finding')}"},
            "properties": {
                "status": f.get("status"),
                "severity": f.get("severity"),
                "citation": f.get("citation", ""),
            },
        })
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": tool_name,
                "version": version,
                "informationUri": "https://github.com/griddyaf/hipaa-audit-suite",
                "rules": rules,
            }},
            "results": results,
        }],
    }


def write_sarif(findings, path):
    with open(path, "w") as f:
        json.dump(to_sarif(findings), f, indent=2)
    return path
