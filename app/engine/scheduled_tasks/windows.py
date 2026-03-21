from __future__ import annotations

import csv
import io
from typing import Any, Dict, List

from ..common_utils import make_finding, suspicious_path, run_command


SCRIPT_HINTS = ("powershell", "pwsh", "cmd.exe", "wscript", "cscript", "mshta", "python", "curl", "wget")
SAFE_MICROSOFT_BINARIES = (
    "rundll32.exe",
    "dllhost.exe",
    "svchost.exe",
    "conhost.exe",
    "backgroundtaskhost.exe",
    "usoclient.exe",
    "musnotification.exe",
    "musnotificationux.exe",
    "dsregcmd.exe",
)


def _task_key(task_name: str, action: str, status: str) -> tuple[str, str, str]:
    return (task_name.strip().lower(), action.strip().lower(), status.strip().lower())


def _is_low_signal_microsoft_task(task_name: str, action: str) -> bool:
    normalized_name = task_name.strip().lower()
    normalized_action = action.strip().lower()
    if not normalized_name.startswith("\\microsoft\\windows\\"):
        return False
    if suspicious_path(action):
        return False
    return any(binary in normalized_action for binary in SAFE_MICROSOFT_BINARIES)


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
    seen_items: set[tuple[str, str, str]] = set()
    seen_findings: set[tuple[str, str]] = set()

    reader = csv.DictReader(io.StringIO(stdout))
    for row in reader:
        task_name = row.get("TaskName", "") or row.get("Task Name", "")
        action = row.get("Task To Run", "") or row.get("Actions", "")
        status = row.get("Status", "")
        dedupe_key = _task_key(task_name, action, status)
        if dedupe_key in seen_items:
            continue
        seen_items.add(dedupe_key)

        item = {
            "task_name": task_name,
            "label": task_name,
            "action": action,
            "status": status,
            "author": row.get("Author", ""),
        }
        items.append(item)

        low_action = action.lower()
        if _is_low_signal_microsoft_task(task_name, action):
            continue

        if suspicious_path(action):
            detail = f"Automatic task launches from a user-controlled or unusual path: {task_name}"
            if ("scheduled_tasks", detail) not in seen_findings:
                findings.append(make_finding("scheduled_tasks", detail, 6, item))
                seen_findings.add(("scheduled_tasks", detail))
        elif any(token in low_action for token in SCRIPT_HINTS):
            detail = f"Automatic task can run commands or scripts: {task_name}"
            if ("scheduled_tasks", detail) not in seen_findings:
                findings.append(make_finding("scheduled_tasks", detail, 4, item))
                seen_findings.add(("scheduled_tasks", detail))

    return {
        "component": "scheduled_tasks",
        "items": items,
        "findings": findings,
        "error": "",
    }
