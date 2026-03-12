from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Set, Tuple


APP_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = APP_DIR / "data"
HISTORY_DIR = DATA_DIR / "behavior_history"
HISTORY_DIR.mkdir(exist_ok=True)


def _connection_keys(report: Dict[str, Any]) -> Set[Tuple[str, int, str]]:
    items = report.get("active_connections", {}).get("items", [])
    out = set()
    for x in items:
        out.add((
            str(x.get("name", "")),
            int(x.get("remote_port", 0)),
            str(x.get("remote_addr", "")),
        ))
    return out


def _listening_keys(report: Dict[str, Any]) -> Set[Tuple[str, int]]:
    items = report.get("listening_ports", {}).get("items", [])
    return {
        (str(x.get("name", "")), int(x.get("local_port", 0)))
        for x in items
    }


def _extension_keys(report: Dict[str, Any]) -> Set[Tuple[str, str]]:
    items = report.get("browser_extensions", {}).get("items", [])
    return {
        (str(x.get("browser", "")), str(x.get("id", "")))
        for x in items
    }


def save_snapshot(report: Dict[str, Any]) -> Path:
    stamp = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    path = HISTORY_DIR / f"{stamp}.json"
    payload = {
        "saved_at": stamp,
        "connections": sorted(list(_connection_keys(report))),
        "listening_ports": sorted(list(_listening_keys(report))),
        "extensions": sorted(list(_extension_keys(report))),
    }
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return path


def load_latest_snapshot() -> Dict[str, Any] | None:
    files = sorted(HISTORY_DIR.glob("*.json"))
    if not files:
        return None
    return json.loads(files[-1].read_text(encoding="utf-8"))


def diff_behavior(report: Dict[str, Any], previous: Dict[str, Any] | None) -> Dict[str, Any]:
    current_connections = _connection_keys(report)
    current_listening = _listening_keys(report)
    current_extensions = _extension_keys(report)

    old_connections = set(tuple(x) for x in previous.get("connections", [])) if previous else set()
    old_listening = set(tuple(x) for x in previous.get("listening_ports", [])) if previous else set()
    old_extensions = set(tuple(x) for x in previous.get("extensions", [])) if previous else set()

    return {
        "new_connections": sorted(list(current_connections - old_connections)),
        "new_listening_ports": sorted(list(current_listening - old_listening)),
        "new_extensions": sorted(list(current_extensions - old_extensions)),
    }


def format_behavior_diff(diff: Dict[str, Any]) -> str:
    lines: List[str] = []
    new_connections = diff.get("new_connections", [])
    new_listening = diff.get("new_listening_ports", [])
    new_extensions = diff.get("new_extensions", [])

    lines.append("Behavior Since Last Scan:")

    if not new_connections and not new_listening and not new_extensions:
        lines.append("- No new behavior detected")
        return "\n".join(lines)

    if new_connections:
        lines.append("- New public/process connections:")
        for name, port, addr in new_connections[:10]:
            lines.append(f"  • {name} -> {addr}:{port}")

    if new_listening:
        lines.append("- New listening ports:")
        for name, port in new_listening[:10]:
            lines.append(f"  • {name} listening on {port}")

    if new_extensions:
        lines.append("- New browser extensions observed:")
        for browser, ext_id in new_extensions[:10]:
            lines.append(f"  • {browser}: {ext_id}")

    return "\n".join(lines)
