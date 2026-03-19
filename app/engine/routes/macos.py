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
    default_routes: List[Dict[str, Any]] = []

    try:
        output = subprocess.check_output(
            ["netstat", "-rn"],
            text=True,
            stderr=subprocess.STDOUT,
        )
    except Exception as exc:
        return {
            "component": "routes",
            "default_routes": [],
            "findings": [make_finding("routes", "Failed to read routing table", 3, {"error": str(exc)})],
            "raw": "",
            "error": str(exc),
        }

    for line in output.splitlines():
        parts = line.split()
        if len(parts) >= 4 and parts[0] == "default":
            default_routes.append(
                {
                    "destination": parts[0],
                    "gateway": parts[1],
                    "flags": parts[2],
                    "interface": parts[3],
                }
            )

    if len(default_routes) > 1:
        findings.append(
            make_finding(
                "routes",
                "Multiple default routes detected",
                4,
                {"default_routes": default_routes},
            )
        )

    return {
        "component": "routes",
        "default_routes": default_routes,
        "findings": findings,
        "raw": output[:12000],
        "error": "",
    }
