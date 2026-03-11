from __future__ import annotations
import json
from datetime import datetime
from pathlib import Path

APP_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = APP_DIR / "data"
HISTORY_DIR = DATA_DIR / "behavior_history"
HISTORY_DIR.mkdir(exist_ok=True)

def save_snapshot(report):

    stamp=datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    path=HISTORY_DIR / f"{stamp}.json"

    payload={
        "timestamp":stamp,
        "connections":report.get("active_connections",{}),
        "ports":report.get("listening_ports",{}),
        "extensions":report.get("browser_extensions",{})
    }

    path.write_text(json.dumps(payload,indent=2),encoding="utf-8")
    return path

def load_last_snapshot():

    files=sorted(HISTORY_DIR.glob("*.json"))
    if not files:
        return None

    return json.loads(files[-1].read_text())

def diff_snapshot(report,last):

    if not last:
        return {"new_items":[]}

    current=report.get("active_connections",{})
    previous=last.get("connections",{})

    new=set(str(x) for x in current)-set(str(x) for x in previous)

    return {"new_connections":list(new)}
