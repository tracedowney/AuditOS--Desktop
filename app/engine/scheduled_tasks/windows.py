from __future__ import annotations

import csv
import io
from typing import Any, Dict, List

from ..common_utils import make_finding, suspicious_path, run_command


SCRIPT_HINTS = ("powershell", "pwsh", "cmd.exe", "wscript", "cscript", "mshta", "python", "curl", "wget")


def run():
    code, stdout, stderr = run_command(["schtasks", "/query", "/fo", "csv", "/v"])
    if code != 0:
        return {
            "component": "scheduled_tasks",
            "items": [],
            "findings": [make_finding("scheduled_tasks", "Failed to enumerate scheduled tasks", 3, {"error": stderr})],
            "error": stderr.strip(),
        }

    items: List[Dict[str, Any]] = []
    findings: List[Dict[str, Any]] = []

    reader = csv.DictReader(io.StringIO(stdout))
    for row in reader:
        task_name = row.get("TaskName", "") or row.get("Task Name", "")
        action = row.get("Task To Run", "") or row.get("Actions", "")
        status = row.get("Status", "")
        item = {
            "task_name": task_name,
            "label": task_name,
            "action": action,
            "status": status,
            "author": row.get("Author", ""),
        }
        items.append(item)

        low_action = action.lower()
        if suspicious_path(action):
            findings.append(make_finding("scheduled_tasks", f"Scheduled task runs from review-worthy path: {task_name}", 6, item))
        elif any(token in low_action for token in SCRIPT_HINTS):
            findings.append(make_finding("scheduled_tasks", f"Scheduled task launches script-capable binary: {task_name}", 4, item))

    return {
        "component": "scheduled_tasks",
        "items": items,
        "findings": findings,
        "error": "",
    }
