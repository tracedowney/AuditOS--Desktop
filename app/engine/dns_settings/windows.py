from __future__ import annotations

import subprocess


def run():
    items = []
    findings = []

    try:
        output = subprocess.check_output(
            ["ipconfig", "/all"],
            text=True,
            encoding="utf-8",
            errors="ignore",
        )

        current_adapter = None

        for line in output.splitlines():
            if line and not line.startswith(" "):
                current_adapter = line.strip(" :")
                continue

            if "DNS Servers" in line:
                value = line.split(":", 1)[-1].strip()
                if value:
                    items.append({
                        "adapter": current_adapter or "unknown",
                        "dns_servers": [value],
                    })
                    findings.append({
                        "severity": "medium",
                        "category": "dns",
                        "detail": f"Review DNS server on {current_adapter}: {value}",
                    })

        return {
            "component": "dns_settings",
            "adapters": items,
            "findings": findings,
            "error": "",
        }

    except Exception as e:
        return {
            "component": "dns_settings",
            "adapters": [],
            "findings": [],
            "error": str(e),
        }
