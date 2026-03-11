from __future__ import annotations

import platform
from typing import Any, Dict

from engine.run_full_audit import build_report


def run_audit(mode: str = "quick") -> Dict[str, Any]:
    report = build_report(mode=mode)
    report.setdefault("meta", {})
    report["meta"]["mode"] = mode
    report["meta"]["host_os"] = platform.platform()
    return report
