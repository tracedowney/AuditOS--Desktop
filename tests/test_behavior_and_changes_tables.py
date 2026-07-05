from __future__ import annotations

import importlib
import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication


def _app() -> QApplication:
    return QApplication.instance() or QApplication([])


def test_behavior_table_uses_plain_language_explanations():
    module = importlib.import_module("ui.behavior_table")
    module = importlib.reload(module)

    app = _app()
    table = module.BehaviorTable()
    table.load_behavior(
        {
            "has_previous": True,
            "new_connections": [("python.exe", 443, "8.8.8.8")],
            "new_listening_ports": [],
            "new_extensions": [],
            "new_dns_servers": [],
            "new_startup_items": [],
            "new_scheduled_tasks": [],
        }
    )

    assert table.item(0, 0).text() == "New Internet Activity"
    assert "started talking to" in table.item(0, 2).text()
    assert "connected to a web service on the internet" in table.item(0, 2).toolTip()

    table.deleteLater()
    app.processEvents()


def test_behavior_table_explains_macos_launchd_jobs_in_plain_language():
    module = importlib.import_module("ui.behavior_table")
    module = importlib.reload(module)

    app = _app()
    table = module.BehaviorTable()
    table.load_behavior(
        {
            "has_previous": True,
            "new_connections": [],
            "new_listening_ports": [],
            "new_extensions": [],
            "new_dns_servers": [],
            "new_startup_items": [],
            "new_scheduled_tasks": [
                "com.apple.mdworker.shared",
                "application.com.apple.Passwords",
            ],
        }
    )

    assert table.item(0, 1).text() == "macOS Spotlight metadata worker"
    assert "Spotlight metadata worker" in table.item(0, 2).text()
    assert "temporary system churn" in table.item(0, 2).toolTip()
    assert table.item(1, 1).text() == "Apple Passwords app helper"
    assert "launchd helper entry" in table.item(1, 2).text()
    assert "less suspicious" in table.item(1, 2).toolTip()

    table.deleteLater()
    app.processEvents()


def test_changes_table_explains_why_dns_change_matters():
    module = importlib.import_module("ui.changes_table")
    module = importlib.reload(module)

    app = _app()
    table = module.ChangesTable()
    table.load_changes(
        [
            {
                "category": "dns",
                "severity": "medium",
                "title": "New DNS server",
                "detail": "New DNS server detected: 1.1.1.1",
            }
        ]
    )

    assert table.item(0, 2).text() == "DNS server added"
    assert "started using DNS server 1.1.1.1" in table.item(0, 3).text()
    assert "privacy" in table.item(0, 3).text().lower()

    table.deleteLater()
    app.processEvents()


def test_findings_table_exposes_supporting_detail_text():
    module = importlib.import_module("ui.findings_table")
    module = importlib.reload(module)

    app = _app()
    table = module.FindingsTable()
    table.load_findings(
        [
            {
                "severity": "medium",
                "category": "dns",
                "detail": "Review custom public DNS server on 3 resolver entries: 79.127.185.11",
                "evidence": {
                    "explanation": "This DNS server appears repeatedly across resolver entries, so it likely represents one custom resolver choice rather than three separate issues.",
                    "impact_hint": "Unexpected DNS servers can affect privacy, filtering, or where web traffic gets routed for name lookups.",
                    "exe": "/usr/sbin/scutil",
                },
            }
        ]
    )

    detail = table.detail_text_at_row(0)

    assert "custom resolver choice" in detail
    assert "Possible impact:" in detail
    assert "Path: /usr/sbin/scutil" in detail

    table.deleteLater()
    app.processEvents()
