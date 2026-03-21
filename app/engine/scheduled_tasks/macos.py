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


def suspicious_path(path: str) -> bool:
    p = path.lower()
    return any(x in p for x in [
        "/tmp/",
        "/downloads/",
        "/desktop/",
        "/private/tmp/",
    ])


def run():
    items: List[Dict[str, Any]] = []
    findings: List[Dict[str, Any]] = []

    try:
        output = subprocess.check_output(
            ["launchctl", "list"],
            text=True,
            stderr=subprocess.STDOUT,
        )
    except Exception as exc:
        return {
            "component": "scheduled_tasks",
            "items": [],
            "findings": [
                make_finding("scheduled_tasks", "Failed to enumerate launchctl jobs", 3, {"error": str(exc)})
            ],
            "error": str(exc),
        }

    lines = output.splitlines()
    for line in lines[1:]:
        parts = line.split(None, 2)
        if len(parts) < 3:
            continue

        pid, status, label = parts[0], parts[1], parts[2]

        item = {
            "label": label,
            "pid": pid,
            "status": status,
        }
        items.append(item)

        low_label = label.lower()
        if any(x in low_label for x in ["tmp", "download", "desktop", "script", "python", "osascript", "curl", "wget"]):
            findings.append(
                make_finding(
                    "scheduled_tasks",
                    f"Review launchctl job: {label}",
                    3,
                    item,
                )
            )

    return {
        "component": "scheduled_tasks",
        "items": items,
        "findings": findings,
        "error": "",
    }
