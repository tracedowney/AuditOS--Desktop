from __future__ import annotations

import os
import platform
from pathlib import Path


APP_NAME = "AuditOS"


def get_user_data_dir() -> Path:
    system = platform.system()

    if system == "Windows":
        base = os.environ.get("APPDATA")
        if base:
            return Path(base) / APP_NAME
        return Path.home() / "AppData" / "Roaming" / APP_NAME

    if system == "Darwin":
        return Path.home() / "Library" / "Application Support" / APP_NAME

    xdg = os.environ.get("XDG_DATA_HOME")
    if xdg:
        return Path(xdg) / APP_NAME
    return Path.home() / ".local" / "share" / APP_NAME


def ensure_user_data_dir() -> Path:
    path = get_user_data_dir()
    path.mkdir(parents=True, exist_ok=True)
    return path
