from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Set, Tuple
from services.app_paths import ensure_user_data_dir

APP_DIR = Path(__file__).resolve().parent.parent
LEGACY_DATA_DIR = APP_DIR / "data"
DATA_DIR = ensure_user_data_dir()
HISTORY_DIR = DATA_DIR / "behavior_history"
HISTORY_DIR.mkdir(parents=True, exist_ok=True)
LEGACY_HISTORY_DIR = LEGACY_DATA_DIR / "behavior_history"


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
    return {(str(x.get("name", "")), int(x.get("local_port", 0))) for x in items}


def _extension_keys(report: Dict[str, Any]) -> Set[Tuple[str, str]]:
    items = report.get("browser_extensions", {}).get("items", [])
    return {(str(x.get("browser", "")), str(x.get("id", ""))) for x in items}


def _dns_keys(report: Dict[str, Any]) -> Set[str]:
    out = set()
    for adapter in report.get("dns_settings", {}).get("adapters", []):
        for server in adapter.get("dns_servers", []):
            out.add(str(server))
    return out


def _startup_keys(report: Dict[str, Any]) -> Set[str]:
    startup = report.get("startup_items", {})
    items = startup.get("items", [])
    if not items:
        normalized = []
        for entry in startup.get("run_keys", []):
            if not isinstance(entry, dict):
                continue
            for value in entry.get("values", []):
                if isinstance(value, dict):
                    normalized.append({
                        "label": str(value.get("name", "")),
                        "path": str(value.get("data", "")),
                    })
        for path in startup.get("startup_folder_items", []):
            normalized.append({
                "label": str(path).split("\\")[-1],
                "path": str(path),
            })
        items = normalized
    return {str(x.get("label", x.get("path", x.get("program", "")))) for x in items}


def _task_keys(report: Dict[str, Any]) -> Set[str]:
    items = report.get("scheduled_tasks", {}).get("items", [])
    return {str(x.get("label", x.get("task_name", ""))) for x in items}


def save_snapshot(report: Dict[str, Any]) -> Path:
    stamp = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    path = HISTORY_DIR / f"{stamp}.json"
    payload = {
        "saved_at": stamp,
        "connections": sorted(list(_connection_keys(report))),
        "listening_ports": sorted(list(_listening_keys(report))),
        "extensions": sorted(list(_extension_keys(report))),
        "dns_servers": sorted(list(_dns_keys(report))),
        "startup_items": sorted(list(_startup_keys(report))),
        "scheduled_tasks": sorted(list(_task_keys(report))),
    }
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return path


def load_latest_snapshot() -> Dict[str, Any] | None:
    files = sorted(HISTORY_DIR.glob("*.json"))
    if not files and LEGACY_HISTORY_DIR.exists():
        files = sorted(LEGACY_HISTORY_DIR.glob("*.json"))
    if not files:
        return None
    return json.loads(files[-1].read_text(encoding="utf-8"))


def diff_behavior(report: Dict[str, Any], previous: Dict[str, Any] | None) -> Dict[str, Any]:
    current_connections = _connection_keys(report)
    current_listening = _listening_keys(report)
    current_extensions = _extension_keys(report)
    current_dns = _dns_keys(report)
    current_startup = _startup_keys(report)
    current_tasks = _task_keys(report)

    old_connections = set(tuple(x) for x in previous.get("connections", [])) if previous else set()
    old_listening = set(tuple(x) for x in previous.get("listening_ports", [])) if previous else set()
    old_extensions = set(tuple(x) for x in previous.get("extensions", [])) if previous else set()
    old_dns = set(previous.get("dns_servers", [])) if previous else set()
    old_startup = set(previous.get("startup_items", [])) if previous else set()
    old_tasks = set(previous.get("scheduled_tasks", [])) if previous else set()

    return {
        "has_previous": previous is not None,
        "new_connections": sorted(list(current_connections - old_connections)),
        "new_listening_ports": sorted(list(current_listening - old_listening)),
        "new_extensions": sorted(list(current_extensions - old_extensions)),
        "new_dns_servers": sorted(list(current_dns - old_dns)),
        "new_startup_items": sorted(list(current_startup - old_startup)),
        "new_scheduled_tasks": sorted(list(current_tasks - old_tasks)),
    }


def format_behavior_diff(diff: Dict[str, Any]) -> str:
    lines: List[str] = []
    has_previous = bool(diff.get("has_previous"))
    new_connections = diff.get("new_connections", [])
    new_listening = diff.get("new_listening_ports", [])
    new_extensions = diff.get("new_extensions", [])
    new_dns = diff.get("new_dns_servers", [])
    new_startup = diff.get("new_startup_items", [])
    new_tasks = diff.get("new_scheduled_tasks", [])

    lines.append("Behavior Since Last Scan:")

    if not any([new_connections, new_listening, new_extensions, new_dns, new_startup, new_tasks]):
        if has_previous:
            lines.append("- No new behavior detected")
        else:
            lines.append("- No previous scan snapshot yet; future scans will show new behavior here")
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

    if new_dns:
        lines.append("- New DNS servers observed:")
        for server in new_dns[:10]:
            lines.append(f"  • {server}")

    if new_startup:
        lines.append("- New startup items observed:")
        for item in new_startup[:10]:
            lines.append(f"  • {item}")

    if new_tasks:
        lines.append("- New scheduled tasks observed:")
        for task in new_tasks[:10]:
            lines.append(f"  • {task}")

    return "\n".join(lines)
