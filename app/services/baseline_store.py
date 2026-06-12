from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional
from services.app_paths import ensure_user_data_dir
from version_info import APP_VERSION, PERSISTENCE_VERSION

APP_DIR = Path(__file__).resolve().parent.parent
LEGACY_DATA_DIR = APP_DIR / "data"
DATA_DIR = ensure_user_data_dir()

BASELINE_PATH = DATA_DIR / "baseline.json"
LAST_REPORT_PATH = DATA_DIR / "last_report.json"
SETTINGS_PATH = DATA_DIR / "settings.json"


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _save(path: Path, data: Dict[str, Any]):
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


def _load(path: Path) -> Optional[Dict[str, Any]]:
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def _is_current_payload(data: Dict[str, Any] | None) -> bool:
    if not isinstance(data, dict):
        return False
    return (
        data.get("app_version") == APP_VERSION
        and data.get("data_version") == PERSISTENCE_VERSION
        and isinstance(data.get("report"), dict)
    )


def _load_versioned(path: Path) -> Optional[Dict[str, Any]]:
    data = _load(path)
    if not _is_current_payload(data):
        return None
    return data


def _make_report_payload(report: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "saved_at": _utc_now_iso(),
        "app_version": APP_VERSION,
        "data_version": PERSISTENCE_VERSION,
        "report": report,
    }


def save_baseline(report: Dict[str, Any]):
    _save(BASELINE_PATH, _make_report_payload(report))


def load_baseline():
    return _load_versioned(BASELINE_PATH)


def save_last_report(report: Dict[str, Any]):
    _save(LAST_REPORT_PATH, _make_report_payload(report))


def load_last_report():
    return _load_versioned(LAST_REPORT_PATH)


def load_settings():
    data = _load(SETTINGS_PATH)
    if data:
        return data

    return {
        "schedule_enabled": False,
        "schedule_frequency": "weekly",
        "schedule_mode": "quick",
        "ai_enabled": False,
        "license_tier": "free",
    }


def save_settings(data: Dict[str, Any]):
    _save(SETTINGS_PATH, data)
