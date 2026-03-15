from __future__ import annotations

import winreg


def run():
    items = []
    findings = []

    keys = [
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
    ]

    for root, path in keys:
        try:
            with winreg.OpenKey(root, path) as key:
                i = 0
                while True:
                    try:
                        name, value, _ = winreg.EnumValue(key, i)
                        items.append({
                            "name": name,
                            "command": value,
                            "location": path,
                        })
                        findings.append({
                            "severity": "medium",
                            "category": "startup_items",
                            "detail": f"Startup item: {name}",
                        })
                        i += 1
                    except OSError:
                        break
        except Exception:
            pass

    return {
        "component": "startup_items",
        "items": items,
        "findings": findings,
        "error": "",
    }
