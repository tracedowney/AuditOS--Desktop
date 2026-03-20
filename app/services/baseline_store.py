from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional
from services.app_paths import ensure_user_data_dir

APP_DIR = Path(__file__).resolve().parent.parent
LEGACY_DATA_DIR = APP_DIR / "data"
DATA_DIR = ensure_user_data_dir()

BASELINE_PATH = DATA_DIR / "baseline.json"
LAST_REPORT_PATH = DATA_DIR / "last_report.json"
SETTINGS_PATH = DATA_DIR / "settings.json"

LEGACY_BASELINE_PATH = LEGACY_DATA_DIR / "baseline.json"
LEGACY_LAST_REPORT_PATH = LEGACY_DATA_DIR / "last_report.json"
LEGACY_SETTINGS_PATH = LEGACY_DATA_DIR / "settings.json"


def _save(path: Path, data: Dict[str, Any]):
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


def _load(path: Path) -> Optional[Dict[str, Any]]:
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def _load_with_legacy(primary: Path, legacy: Path) -> Optional[Dict[str, Any]]:
    data = _load(primary)
    if data is not None:
        return data
    return _load(legacy)


def save_baseline(report: Dict[str, Any]):
    _save(BASELINE_PATH, {
        "saved_at": datetime.utcnow().isoformat() + "Z",
        "report": report
    })


def load_baseline():
    return _load_with_legacy(BASELINE_PATH, LEGACY_BASELINE_PATH)


def save_last_report(report: Dict[str, Any]):
    _save(LAST_REPORT_PATH, {
        "saved_at": datetime.utcnow().isoformat() + "Z",
        "report": report
    })


def load_last_report():
    return _load_with_legacy(LAST_REPORT_PATH, LEGACY_LAST_REPORT_PATH)


def load_settings():
    data = _load_with_legacy(SETTINGS_PATH, LEGACY_SETTINGS_PATH)
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
