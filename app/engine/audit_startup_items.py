from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

from .common_utils import expand, make_finding, run_command, suspicious_path

RUN_KEY_PATHS = [
    r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run",
    r"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run",
    r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    r"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce",
]


def parse_reg_values(stdout: str):
    values = []
    for line in stdout.splitlines():
        parts = re.split(r"\s{2,}", line.strip())
        if len(parts) >= 3 and not parts[0].startswith("HKEY_"):
            values.append({"name": parts[0], "type": parts[1], "data": parts[2]})
    return values


def audit_startup_items():
    items = []
    findings = []

    for key in RUN_KEY_PATHS:
        code, stdout, stderr = run_command(["reg", "query", key])
        values = parse_reg_values(stdout) if code == 0 else []
        items.append({"source": key, "values": values, "error": stderr.strip()})

        for value in values:
            data = value["data"]
            if suspicious_path(data):
                findings.append(make_finding("startup_items", f"Startup entry from temp/downloads/appdata: {value['name']}", 8, {"key": key, "data": data}))
            elif "powershell" in data.lower() or "wscript" in data.lower() or "cmd.exe /c" in data.lower():
                findings.append(make_finding("startup_items", f"Script-style startup entry: {value['name']}", 6, {"key": key, "data": data}))

    startup_dirs = [
        expand(r"~\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"),
        Path(r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"),
    ]
    startup_files = []

    for d in startup_dirs:
        if d.exists():
            for child in d.iterdir():
                startup_files.append(str(child))
                if suspicious_path(str(child)):
                    findings.append(make_finding("startup_items", f"Startup folder item in suspicious path: {child.name}", 8, {"path": str(child)}))

    return {
        "component": "startup_items",
        "run_keys": items,
        "startup_folder_items": startup_files,
        "findings": findings,
    }


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--pretty", action="store_true")
    args = ap.parse_args()
    print(json.dumps(audit_startup_items(), indent=2 if args.pretty else None))