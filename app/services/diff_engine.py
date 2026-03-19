from __future__ import annotations

from typing import Any, Dict, List, Set, Tuple


def _startup_items(report: Dict[str, Any]) -> List[Dict[str, Any]]:
    startup = report.get("startup_items", {})
    items = startup.get("items", [])
    if isinstance(items, list) and items:
        return items

    normalized: List[Dict[str, Any]] = []
    for entry in startup.get("run_keys", []):
        if not isinstance(entry, dict):
            continue
        source = str(entry.get("source", ""))
        for value in entry.get("values", []):
            if isinstance(value, dict):
                normalized.append({
                    "label": str(value.get("name", "")),
                    "path": str(value.get("data", "")),
                    "source": source,
                })

    for path in startup.get("startup_folder_items", []):
        normalized.append({
            "label": str(path).split("\\")[-1],
            "path": str(path),
            "source": "startup_folder",
        })

    return normalized


def _extensions(report: Dict[str, Any]) -> Set[Tuple[str, str, str]]:
    items = report.get("browser_extensions", {}).get("items", [])
    return {
        (
            str(x.get("browser", "")),
            str(x.get("profile", "")),
            str(x.get("id", "")),
        )
        for x in items
    }


def _tasks(report: Dict[str, Any]) -> Set[str]:
    items = report.get("scheduled_tasks", {}).get("items", [])
    return {str(x.get("label", x.get("task_name", ""))) for x in items}


def _startup(report: Dict[str, Any]) -> Set[str]:
    items = _startup_items(report)
    return {str(x.get("label", x.get("path", x.get("program", "")))) for x in items}


def _ports(report: Dict[str, Any]) -> Set[Tuple[str, int]]:
    items = report.get("listening_ports", {}).get("items", [])
    return {(str(x.get("name", "")), int(x.get("local_port", 0))) for x in items}


def _dns(report: Dict[str, Any]) -> Set[str]:
    out = set()
    for adapter in report.get("dns_settings", {}).get("adapters", []):
        for server in adapter.get("dns_servers", []):
            out.add(str(server))
    return out


def _proxy(report: Dict[str, Any]) -> Set[str]:
    proxy = report.get("proxy_settings", {})
    out = set()
    if proxy.get("proxy_enable"):
        out.add(f"proxy:{proxy.get('proxy_server', '')}")
    if proxy.get("auto_config_url"):
        out.add(f"pac:{proxy.get('auto_config_url', '')}")
    return out


def build_diff(old_report: Dict[str, Any], new_report: Dict[str, Any]) -> Dict[str, Any]:
    changes: List[Dict[str, Any]] = []

    for item in sorted(_extensions(new_report) - _extensions(old_report)):
        changes.append({
            "category": "extension",
            "severity": "medium",
            "title": "New browser extension",
            "detail": f"New extension detected: browser={item[0]} profile={item[1]} id={item[2]}",
        })

    for task in sorted(_tasks(new_report) - _tasks(old_report)):
        changes.append({
            "category": "scheduled_task",
            "severity": "medium",
            "title": "New scheduled task",
            "detail": f"New scheduled task detected: {task}",
        })

    for item in sorted(_startup(new_report) - _startup(old_report)):
        changes.append({
            "category": "startup_item",
            "severity": "medium",
            "title": "New startup item",
            "detail": f"New startup item detected: {item}",
        })

    for proc, port in sorted(_ports(new_report) - _ports(old_report)):
        changes.append({
            "category": "listening_port",
            "severity": "medium",
            "title": "New listening port",
            "detail": f"New listening port detected: {proc} on port {port}",
        })

    for server in sorted(_dns(new_report) - _dns(old_report)):
        changes.append({
            "category": "dns",
            "severity": "medium",
            "title": "New DNS server",
            "detail": f"New DNS server detected: {server}",
        })

    for proxy_item in sorted(_proxy(new_report) - _proxy(old_report)):
        changes.append({
            "category": "proxy",
            "severity": "medium",
            "title": "Proxy configuration changed",
            "detail": f"New proxy-related setting detected: {proxy_item}",
        })

    return {"count": len(changes), "changes": changes}
