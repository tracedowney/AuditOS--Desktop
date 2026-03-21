from __future__ import annotations

import argparse
import csv
import io
import json

from .common_utils import make_finding, run_command, suspicious_path

SAFE_SCRIPT_HOST_TASK_HINTS = [
    r"\microsoft\windows\workplace join\\",
    r"\microsoft\windows\windowsupdate\\",
    r"\microsoft\windows\defrag\\",
    r"\microsoft\windows\diskcleanup\\",
]


def _is_header_row(task_name: str, task_to_run: str, status: str) -> bool:
    return (
        task_name.strip().lower() == "taskname"
        and task_to_run.strip().lower() in {"task to run", "actions"}
        and status.strip().lower() == "status"
    )


def _is_microsoft_task(task_name: str) -> bool:
    low_name = task_name.strip().lower()
    return low_name.startswith(r"\microsoft\\")


def audit_scheduled_tasks():
    code, stdout, stderr = run_command(["schtasks", "/query", "/fo", "csv", "/v"])
    items = []
    findings = []

    if code == 0 and stdout.strip():
        reader = csv.DictReader(io.StringIO(stdout))
        for row in reader:
            task_name = (row.get("TaskName", "") or "").strip()
            task_to_run = (row.get("Task To Run", "") or row.get("Actions", "") or "").strip()
            status = (row.get("Status", "") or "").strip()

            if not task_name and not task_to_run and not status:
                continue

            if _is_header_row(task_name, task_to_run, status):
                continue

            items.append(
                {
                    "task_name": task_name,
                    "task_to_run": task_to_run,
                    "status": status,
                }
            )

            low_name = task_name.lower()
            low_run = task_to_run.lower()

            if suspicious_path(task_to_run):
                findings.append(
                    make_finding(
                        "scheduled_tasks",
                        f"Task runs from suspicious path: {task_name}",
                        8,
                        {"task_to_run": task_to_run},
                    )
                )
                continue

            launches_script_host = any(
                x in low_run
                for x in ["powershell", "wscript", "cmd.exe /c", "mshta", "python.exe", "pythonw.exe", "cscript", "rundll32.exe"]
            )

            is_microsoft_task = _is_microsoft_task(task_name)
            is_known_safe_microsoft_bucket = any(h in low_name for h in SAFE_SCRIPT_HOST_TASK_HINTS)

            if launches_script_host:
                if is_known_safe_microsoft_bucket:
                    findings.append(
                        make_finding(
                            "scheduled_tasks",
                            f"Review Microsoft task using script host: {task_name}",
                            1,
                            {"task_to_run": task_to_run},
                        )
                    )
                elif is_microsoft_task:
                    findings.append(
                        make_finding(
                            "scheduled_tasks",
                            f"Review Microsoft task using script host: {task_name}",
                            2,
                            {"task_to_run": task_to_run},
                        )
                    )
                else:
                    findings.append(
                        make_finding(
                            "scheduled_tasks",
                            f"Task launches script host/interpreter: {task_name}",
                            5,
                            {"task_to_run": task_to_run},
                        )
                    )
    else:
        findings.append(make_finding("scheduled_tasks", "Failed to enumerate scheduled tasks", 3, {"error": stderr}))

    return {
        "component": "scheduled_tasks",
        "items": items,
        "findings": findings,
        "error": stderr.strip(),
    }


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--pretty", action="store_true")
    args = ap.parse_args()
    print(json.dumps(audit_scheduled_tasks(), indent=2 if args.pretty else None))