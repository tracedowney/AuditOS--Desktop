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


def _save(path: Path, data: Dict[str, Any]):
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


def _load(path: Path) -> Optional[Dict[str, Any]]:
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def save_baseline(report: Dict[str, Any]):
    _save(BASELINE_PATH, {
        "saved_at": datetime.utcnow().isoformat() + "Z",
        "report": report
    })


def load_baseline():
    return _load(BASELINE_PATH)


def save_last_report(report: Dict[str, Any]):
    _save(LAST_REPORT_PATH, {
        "saved_at": datetime.utcnow().isoformat() + "Z",
        "report": report
    })


def load_last_report():
    return _load(LAST_REPORT_PATH)


def load_settings():
    data = _load(SETTINGS_PATH)
    if data:
        return data

    return {
        "ai_enabled": False,
        "license_tier": "free",
    }


def save_settings(data: Dict[str, Any]):
    _save(SETTINGS_PATH, data)
