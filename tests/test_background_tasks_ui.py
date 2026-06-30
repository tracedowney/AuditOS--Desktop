from __future__ import annotations

import importlib
import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication


def _app() -> QApplication:
    return QApplication.instance() or QApplication([])


def test_background_tasks_table_loads_review_friendly_rows():
    module = importlib.import_module("ui.background_tasks_table")
    module = importlib.reload(module)

    app = _app()
    table = module.BackgroundTasksTable()
    table.load_tasks(
        [
            {
                "friendly_name": "Windows service host",
                "name": "svchost.exe",
                "role_label": "Likely operating system process",
                "review_label": "Review first",
                "review_reason": "This process name matches a core operating system task, but the file path does not look like the normal system location.",
                "explanation": "Hosts one or more Windows background services.",
                "impact_hint": "Ending it may interrupt Windows features or services that depend on it.",
                "exe": r"C:\Users\alice\Downloads\svchost.exe",
                "cmdline_preview": r"C:\Users\alice\Downloads\svchost.exe",
            }
        ],
        "No tasks loaded.",
    )

    assert table.rowCount() == 1
    assert table.item(0, 0).text() == "Review first"
    assert table.item(0, 1).text() == "Windows service host"
    assert table.item(0, 2).text() == "Likely operating system process"
    assert "Why AuditOS called this out" in table.item(0, 3).toolTip()

    table.deleteLater()
    app.processEvents()


def test_main_window_refreshes_background_task_tab_for_deep_audit(monkeypatch):
    module = importlib.import_module("ui.main_window")
    module = importlib.reload(module)

    monkeypatch.setattr(
        module,
        "load_settings",
        lambda: {
            "schedule_enabled": False,
            "schedule_frequency": "weekly",
            "schedule_mode": "quick",
            "schedule_last_run_at": None,
            "schedule_next_run_at": None,
            "ai_enabled": False,
            "license_tier": "free",
        },
    )
    monkeypatch.setattr(module, "show_first_run_notice", lambda parent=None: None)

    app = _app()
    window = module.MainWindow()

    report = {
        "meta": {"mode": "deep"},
        "background_tasks": {
            "items": [
                {
                    "friendly_name": "PowerShell",
                    "name": "powershell.exe",
                    "role_label": "Script or command host",
                    "review_label": "Review first",
                    "review_status": "review",
                    "review_reason": "This script or command host is running with arguments that often deserve closer review.",
                    "explanation": "PowerShell can run commands or scripts in the background for apps, automation, or admin tasks.",
                    "impact_hint": "Ending it stops the current script or command session. The impact depends on what launched it.",
                    "exe": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                    "cmdline_preview": "powershell.exe -EncodedCommand ...",
                    "pid": 202,
                    "status": "running",
                    "username": "alice",
                }
            ]
        },
    }

    window.refresh_background_tasks_view(report)

    assert "deserve review first" in window.background_tasks_state_label.text()
    assert window.background_tasks_table.rowCount() == 1
    window.background_tasks_table.selectRow(0)
    window.on_background_task_selected()
    assert "Possible impact if ended" in window.background_task_detail.text()
    assert "PowerShell" in window.background_task_detail.text()

    window.schedule_timer.stop()
    window.close()
    window.deleteLater()
    app.processEvents()
