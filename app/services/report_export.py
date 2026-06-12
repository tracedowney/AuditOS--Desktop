from __future__ import annotations

from datetime import datetime


def report_generated_at_local() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def default_report_filename(report: dict | None) -> str:
    meta = report.get("meta", {}) if isinstance(report, dict) else {}

    mode = str(meta.get("mode", "audit")).strip().lower()
    mode_label = {
        "quick": "Quick_Audit",
        "deep": "Deep_Audit",
    }.get(mode, "Audit")

    stamp = _filename_timestamp(meta.get("generated_at"))
    return f"AuditOS_{mode_label}_{stamp}.json"


def _filename_timestamp(value: object) -> str:
    if isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value)
            return parsed.strftime("%Y%m%d_%H%M%S")
        except ValueError:
            pass
    return datetime.now().astimezone().strftime("%Y%m%d_%H%M%S")
