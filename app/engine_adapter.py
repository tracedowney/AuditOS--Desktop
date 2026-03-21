from __future__ import annotations

import platform
from typing import Any, Dict

try:
    from .engine.run_full_audit import build_report
except ImportError:
    from app.engine.run_full_audit import build_report


def run_audit(mode: str = "quick") -> Dict[str, Any]:
    report = build_report(mode=mode)
    if mode != "deep":
        for key in ("routes", "active_connections", "listening_ports"):
            report.pop(key, None)
    report.setdefault("meta", {})
    report["meta"]["mode"] = mode
    report["meta"]["host_os"] = platform.platform()
    return report