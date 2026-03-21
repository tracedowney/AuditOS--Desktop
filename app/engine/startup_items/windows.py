from __future__ import annotations

import re
from typing import Any, Dict, List

from ..common_utils import make_finding, suspicious_path, run_command


RUN_KEYS = [
    r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run",
    r"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run",
]

SCRIPT_HINTS = ("powershell", "pwsh", "cmd.exe", "wscript", "cscript", "mshta", "python", "curl", "wget")


def _parse_reg_output(source: str, output: str) -> List[Dict[str, str]]:
    items: List[Dict[str, str]] = []
    for line in output.splitlines():
        parts = re.split(r"\s{2,}", line.strip())
        if len(parts) < 3 or parts[0].startswith("HKEY_"):
            continue
        items.append({"source": source, "label": parts[0], "path": parts[-1]})
    return items


def run():
    items: List[Dict[str, Any]] = []
    findings: List[Dict[str, Any]] = []
    errors: List[str] = []

    for key in RUN_KEYS:
        code, stdout, stderr = run_command(["reg", "query", key])
        if code != 0:
            errors.append(stderr.strip())
            continue
        for item in _parse_reg_output(key, stdout):
            items.append(item)
            low_path = item["path"].lower()
            if suspicious_path(item["path"]):
                findings.append(make_finding("startup_items", f"Startup item launches from review-worthy path: {item['label']}", 6, item))
            elif any(token in low_path for token in SCRIPT_HINTS):
                findings.append(make_finding("startup_items", f"Startup item launches interpreter/script-capable binary: {item['label']}", 4, item))

    if not items and errors:
        findings.append(make_finding("startup_items", "Failed to enumerate Windows startup items", 3, {"errors": errors}))

    return {
        "component": "startup_items",
        "items": items,
        "findings": findings,
        "error": "\n".join(x for x in errors if x),
    }
