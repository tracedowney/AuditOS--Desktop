from __future__ import annotations
import sys
import traceback
from datetime import datetime
from pathlib import Path

APP_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = APP_DIR / "data"
DATA_DIR.mkdir(exist_ok=True)

CRASH_LOG_PATH = DATA_DIR / "crash.log"

def log_message(message: str):
    timestamp = datetime.utcnow().isoformat() + "Z"
    with CRASH_LOG_PATH.open("a", encoding="utf-8") as f:
        f.write(f"[{timestamp}] {message}\n")

def log_exception(exc: BaseException):
    timestamp = datetime.utcnow().isoformat() + "Z"
    tb = "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))
    with CRASH_LOG_PATH.open("a", encoding="utf-8") as f:
        f.write(f"\n[{timestamp}] UNHANDLED EXCEPTION\n")
        f.write(tb)
        f.write("\n")

def install_global_exception_hook():
    def handle_exception(exc_type, exc_value, exc_traceback):
        if issubclass(exc_type, KeyboardInterrupt):
            sys.__excepthook__(exc_type, exc_value, exc_traceback)
            return

        tb = "".join(traceback.format_exception(exc_type, exc_value, exc_traceback))
        timestamp = datetime.utcnow().isoformat() + "Z"

        with CRASH_LOG_PATH.open("a", encoding="utf-8") as f:
            f.write(f"\n[{timestamp}] GLOBAL EXCEPTION\n")
            f.write(tb)
            f.write("\n")

    sys.excepthook = handle_exception
