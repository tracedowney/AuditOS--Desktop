from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List
import plistlib


STARTUP_DIRS = [
    Path("~/Library/LaunchAgents").expanduser(),
    Path("/Library/LaunchAgents"),
    Path("/Library/LaunchDaemons"),
]


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


def parse_plist(path: Path) -> Dict[str, Any] | None:
    try:
        with path.open("rb") as f:
            return plistlib.load(f)
    except Exception:
        return None


def run():
    items: List[Dict[str, Any]] = []
    findings: List[Dict[str, Any]] = []

    for directory in STARTUP_DIRS:
        if not directory.exists():
            continue

        for child in directory.glob("*.plist"):
            data = parse_plist(child)
            if not data:
                continue

            label = str(data.get("Label", child.stem))
            program = data.get("Program")
            program_args = data.get("ProgramArguments", [])
            run_at_load = bool(data.get("RunAtLoad", False))
            keep_alive = data.get("KeepAlive", False)

            executable = ""
            if isinstance(program, str):
                executable = program
            elif isinstance(program_args, list) and program_args:
                executable = str(program_args[0])

            item = {
                "source": str(directory),
                "path": str(child),
                "label": label,
                "program": executable,
                "program_arguments": program_args if isinstance(program_args, list) else [],
                "run_at_load": run_at_load,
                "keep_alive": keep_alive,
            }
            items.append(item)

            if executable and suspicious_path(executable):
                findings.append(
                    make_finding(
                        "startup_items",
                        f"Startup item launches from review-worthy path: {label}",
                        6,
                        {"path": executable, "plist": str(child)},
                    )
                )

            low_exec = executable.lower()
            if any(x in low_exec for x in ["osascript", "bash", "sh", "zsh", "python", "curl", "wget"]):
                findings.append(
                    make_finding(
                        "startup_items",
                        f"Startup item launches interpreter/script-capable binary: {label}",
                        4,
                        {"path": executable, "plist": str(child)},
                    )
                )

    return {
        "component": "startup_items",
        "items": items,
        "findings": findings,
        "error": "",
    }
