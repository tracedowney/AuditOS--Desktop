from __future__ import annotations

import subprocess


def run():
    items = []
    findings = []

    try:
        output = subprocess.check_output(
            ["certutil", "-store", "Root"],
            text=True,
            encoding="utf-8",
            errors="ignore",
        )

        current = {}
        for line in output.splitlines():
            line = line.strip()
            if line.startswith("===="):
                if current:
                    items.append(current)
                    current = {}
            elif "Serial Number:" in line:
                current["serial"] = line.split(":", 1)[1].strip()
            elif "Issuer:" in line:
                current["issuer"] = line.split(":", 1)[1].strip()
            elif "Subject:" in line:
                current["subject"] = line.split(":", 1)[1].strip()

        if current:
            items.append(current)

        return {
            "component": "certificates",
            "items": items[:200],
            "findings": findings,
            "error": "",
        }
    except Exception as e:
        return {
            "component": "certificates",
            "items": [],
            "findings": [],
            "error": str(e),
        }
