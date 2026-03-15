from __future__ import annotations

import subprocess


def run():
    items = []
    findings = []

    try:
        output = subprocess.check_output(
            ["route", "print"],
            text=True,
            encoding="utf-8",
            errors="ignore",
        )

        for line in output.splitlines():
            if line.strip().startswith("0.0.0.0"):
                parts = line.split()
                if len(parts) >= 5:
                    items.append({
                        "destination": parts[0],
                        "netmask": parts[1],
                        "gateway": parts[2],
                        "interface": parts[3],
                        "metric": parts[4],
                    })

        if len(items) > 1:
            findings.append({
                "severity": "medium",
                "category": "routes",
                "detail": "Multiple default routes detected",
            })

        return {
            "component": "routes",
            "items": items,
            "findings": findings,
            "error": "",
        }
    except Exception as e:
        return {
            "component": "routes",
            "items": [],
            "findings": [],
            "error": str(e),
        }
