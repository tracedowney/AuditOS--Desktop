from __future__ import annotations

from pathlib import Path
import json


def run():
    items = []
    findings = []

    roots = [
        Path.home() / "AppData/Local/Microsoft/Edge/User Data",
        Path.home() / "AppData/Local/Google/Chrome/User Data",
    ]

    for root in roots:
        if not root.exists():
            continue

        browser = "edge" if "Edge" in str(root) else "chrome"

        for profile in root.iterdir():
            if not profile.is_dir():
                continue

            ext_settings = profile / "Extensions"
            prefs = profile / "Preferences"

            if ext_settings.exists():
                for ext_id_dir in ext_settings.iterdir():
                    if not ext_id_dir.is_dir():
                        continue

                    ext_id = ext_id_dir.name
                    version_dirs = [x for x in ext_id_dir.iterdir() if x.is_dir()]
                    version = version_dirs[0].name if version_dirs else ""

                    items.append({
                        "browser": browser,
                        "profile": profile.name,
                        "id": ext_id,
                        "version": version,
                    })

            try:
                if prefs.exists():
                    data = json.loads(prefs.read_text(encoding="utf-8"))
                    settings = data.get("extensions", {}).get("settings", {})
                    for ext_id, meta in settings.items():
                        if meta.get("state") == 1:
                            findings.append({
                                "severity": "medium",
                                "category": "browser_extensions",
                                "detail": f"Review extension: {meta.get('manifest', {}).get('name', ext_id)} ({browser})",
                            })
            except Exception:
                pass

    return {
        "component": "browser_extensions",
        "items": items,
        "findings": findings,
        "error": "",
    }
