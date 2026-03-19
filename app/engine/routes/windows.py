from __future__ import annotations

from typing import Any, Dict, List

from ..common_utils import make_finding, run_command


def run():
    code, stdout, stderr = run_command(["route", "print"])
    if code != 0:
        return {
            "component": "routes",
            "default_routes": [],
            "findings": [make_finding("routes", "Failed to read routing table", 3, {"error": stderr})],
            "raw": "",
            "error": stderr.strip(),
        }

    default_routes: List[Dict[str, Any]] = []
    findings: List[Dict[str, Any]] = []

    for line in stdout.splitlines():
        parts = line.split()
        if len(parts) >= 5 and parts[0] == "0.0.0.0" and parts[1] == "0.0.0.0":
            default_routes.append({
                "destination": parts[0],
                "netmask": parts[1],
                "gateway": parts[2],
                "interface": parts[3],
                "metric": parts[4],
            })

    if len(default_routes) > 1:
        findings.append(make_finding("routes", "Multiple default routes detected", 4, {"default_routes": default_routes}))

    return {
        "component": "routes",
        "default_routes": default_routes,
        "findings": findings,
        "raw": stdout[:12000],
        "error": "",
    }
