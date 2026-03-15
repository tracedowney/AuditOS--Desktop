from __future__ import annotations

import csv
import subprocess
from io import StringIO


def run():
    items = []
    findings = []

    try:
        output = subprocess.check_output(
            ["schtasks", "/query", "/fo", "csv", "/v"],
            text=True,
            encoding="utf-8",
            errors="ignore",
        )

        reader = csv.DictReader(StringIO(output))
        for row in reader:
            name = row.get("TaskName", "")
            action = row.get("Task To Run", "") or row.get("Actions", "")
            items.append({
                "task_name": name,
                "action": action,
                "status": row.get("Status", ""),
            })

            low = action.lower()
            if any(x in low for x in ["powershell", "wscript", "cscript", "cmd.exe", ".vbs", ".js", "python"]):
                findings.append({
                    "severity": "medium",
                    "category": "scheduled_tasks",
                    "detail": f"Task launches script host/interpreter: {name}",
                })

        return {
            "component": "scheduled_tasks",
            "items": items,
            "findings": findings,
            "error": "",
        }
    except Exception as e:
        return {
            "component": "scheduled_tasks",
            "items": [],
            "findings": [],
            "error": str(e),
        }
