from __future__ import annotations

from typing import Any, Dict, List


def build_diff(old_report: Dict[str, Any], new_report: Dict[str, Any]):
    changes: List[Dict[str, Any]] = []

    old_ext = old_report.get("browser_extensions", {}).get("items", [])
    new_ext = new_report.get("browser_extensions", {}).get("items", [])

    old_ids = {x.get("id") for x in old_ext}
    new_ids = {x.get("id") for x in new_ext}

    for ext in new_ext:
        if ext.get("id") in (new_ids - old_ids):
            changes.append({
                "category": "extension",
                "severity": "medium",
                "title": "New browser extension",
                "detail": f"{ext.get('name')} ({ext.get('browser')})"
            })

    return {
        "count": len(changes),
        "changes": changes
    }
