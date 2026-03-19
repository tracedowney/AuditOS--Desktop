from __future__ import annotations

import subprocess
from typing import Any, Dict, List


def make_finding(category: str, detail: str, score: int, evidence: Dict[str, Any] | None = None) -> Dict[str, Any]:
    severity = "high" if score >= 8 else "medium" if score >= 4 else "low"
    return {
        "category": category,
        "detail": detail,
        "score": score,
        "severity": severity,
        "evidence": evidence or {},
    }


def run():
    findings: List[Dict[str, Any]] = []

    try:
        output = subprocess.check_output(
            ["security", "find-certificate", "-a", "-p"],
            text=True,
            stderr=subprocess.STDOUT,
        )
    except Exception as exc:
        return {
            "component": "certificates",
            "user_root_count": 0,
            "machine_root_count": 0,
            "user_root_certificates": [],
            "machine_root_sample": [],
            "suspicious_subjects": [],
            "findings": [
                make_finding("certificates", "Failed to read macOS certificates", 3, {"error": str(exc)})
            ],
            "errors": {"macos": str(exc)},
        }

    cert_count = output.count("BEGIN CERTIFICATE")

    return {
        "component": "certificates",
        "user_root_count": cert_count,
        "machine_root_count": cert_count,
        "user_root_certificates": [],
        "machine_root_sample": [],
        "suspicious_subjects": [],
        "findings": findings,
        "errors": {"macos": ""},
    }
