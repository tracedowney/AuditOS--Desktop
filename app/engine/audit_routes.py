from __future__ import annotations

import argparse
import json
import re

from .common_utils import make_finding, run_command


def audit_routes():
    code, stdout, stderr = run_command(["route", "print"])
    findings = []
    default_routes = []

    for line in stdout.splitlines():
        if re.match(r"^\s*0\.0\.0\.0\s+0\.0\.0\.0\s+", line):
            parts = re.split(r"\s+", line.strip())
            if len(parts) >= 4:
                default_routes.append(
                    {
                        "network": parts[0],
                        "mask": parts[1],
                        "gateway": parts[2],
                        "interface": parts[3],
                    }
                )

    if len(default_routes) > 1:
        findings.append(make_finding("routes", "Multiple IPv4 default routes detected", 4, {"default_routes": default_routes}))

    if code != 0:
        findings.append(make_finding("routes", "Failed to read routing table", 3, {"error": stderr}))

    return {
        "component": "routes",
        "default_routes": default_routes,
        "findings": findings,
        "raw": stdout[:12000],
        "error": stderr.strip(),
    }


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--pretty", action="store_true")
    args = ap.parse_args()
    print(json.dumps(audit_routes(), indent=2 if args.pretty else None))