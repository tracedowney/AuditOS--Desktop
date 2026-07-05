from __future__ import annotations

import importlib
import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication


def _app() -> QApplication:
    return QApplication.instance() or QApplication([])


def test_settings_dialog_shows_friendly_schedule_preview(monkeypatch):
    module = importlib.import_module("ui.settings_dialog")
    module = importlib.reload(module)

    monkeypatch.setattr(
        module,
        "load_settings",
        lambda: {
            "schedule_enabled": True,
            "schedule_frequency": "weekly",
            "schedule_mode": "quick",
            "schedule_last_run_at": None,
            "schedule_next_run_at": "2026-07-01T15:30:00Z",
            "ai_enabled": False,
            "license_tier": "free",
        },
    )

    app = _app()
    dialog = module.SettingsDialog()

    preview = dialog.schedule_preview.text()

    assert "while the app is open" in preview
    assert "Next automatic scan:" in preview
    assert "Jul 01, 2026" in preview

    dialog.close()
    dialog.deleteLater()
    app.processEvents()


def test_scheduled_audit_completion_persists_even_if_ui_update_crashes(monkeypatch):
    module = importlib.import_module("ui.main_window")
    module = importlib.reload(module)

    current_settings = {
        "schedule_enabled": False,
        "schedule_frequency": "weekly",
        "schedule_mode": "quick",
        "schedule_last_run_at": None,
        "schedule_next_run_at": "2026-06-30T12:00:00Z",
        "ai_enabled": False,
        "license_tier": "free",
    }
    saved_settings: list[dict] = []

    monkeypatch.setattr(module, "load_settings", lambda: dict(current_settings))
    monkeypatch.setattr(module, "save_settings", lambda data: saved_settings.append(dict(data)))
    monkeypatch.setattr(module, "load_latest_snapshot", lambda require_live_network=False: None)
    monkeypatch.setattr(module, "save_snapshot", lambda report: None)
    monkeypatch.setattr(module, "diff_behavior", lambda report, previous, previous_live_network=None: {})
    monkeypatch.setattr(module, "format_behavior_diff", lambda behavior: "")
    monkeypatch.setattr(module, "load_last_report", lambda: {})
    monkeypatch.setattr(module, "save_last_report", lambda report: None)
    monkeypatch.setattr(module, "load_baseline", lambda: None)
    monkeypatch.setattr(module, "show_first_run_notice", lambda parent=None: None)
    monkeypatch.setattr(module.QMessageBox, "critical", lambda *args, **kwargs: None)

    app = _app()
    window = module.MainWindow()
    monkeypatch.setattr(window, "maybe_explain_limitations", lambda limitations: None)
    monkeypatch.setattr(window, "maybe_prompt_for_baseline", lambda: None)
    monkeypatch.setattr(
        window.findings,
        "load_findings",
        lambda findings: (_ for _ in ()).throw(RuntimeError("ui boom")),
    )

    current_settings["schedule_enabled"] = True
    window.audit_running = True
    window.current_audit_origin = "scheduled"
    report = {
        "meta": {"mode": "quick"},
        "summary": {
            "counts": {"high": 0, "medium": 0, "low": 0},
            "overall_risk": "low",
            "top_findings": [],
            "limitations": [],
            "plain_summary": [],
        },
    }

    window.audit_finished(report)

    assert saved_settings
    latest = saved_settings[-1]
    assert latest["schedule_last_run_at"] is not None
    assert latest["schedule_next_run_at"] is not None
    assert latest["schedule_next_run_at"] != current_settings["schedule_next_run_at"]

    window.schedule_timer.stop()
    window.close()
    window.deleteLater()
    app.processEvents()


def test_format_summary_html_shows_current_scan_timestamp():
    module = importlib.import_module("ui.main_window")
    module = importlib.reload(module)

    html = module.format_summary_html(
        {
            "counts": {"high": 0, "medium": 0, "low": 0},
            "limitations": [],
            "plain_summary": [],
        },
        mode="deep",
        host_os="macOS-15",
        generated_at="2026-07-04T18:33:48-05:00",
    )

    assert "This scorecard reflects the scan that finished on Jul 04, 2026 at 6:33 PM." in html


def test_limited_visibility_scan_shows_informational_banner_and_disables_export_while_running(monkeypatch):
    module = importlib.import_module("ui.main_window")
    module = importlib.reload(module)

    monkeypatch.setattr(module, "load_settings", lambda: {
        "schedule_enabled": False,
        "schedule_frequency": "weekly",
        "schedule_mode": "deep",
        "schedule_last_run_at": None,
        "schedule_next_run_at": None,
        "ai_enabled": False,
        "license_tier": "free",
    })
    monkeypatch.setattr(module, "load_latest_snapshot", lambda require_live_network=False: None)
    monkeypatch.setattr(module, "save_snapshot", lambda report: None)
    monkeypatch.setattr(module, "diff_behavior", lambda report, previous, previous_live_network=None: {})
    monkeypatch.setattr(module, "format_behavior_diff", lambda behavior: "")
    monkeypatch.setattr(module, "load_last_report", lambda: {})
    monkeypatch.setattr(module, "save_last_report", lambda report: None)
    monkeypatch.setattr(module, "load_baseline", lambda: None)
    monkeypatch.setattr(module, "show_first_run_notice", lambda parent=None: None)
    monkeypatch.setattr(module.QMessageBox, "critical", lambda *args, **kwargs: None)

    app = _app()
    window = module.MainWindow()
    monkeypatch.setattr(window, "maybe_explain_limitations", lambda limitations: None)
    monkeypatch.setattr(window, "maybe_prompt_for_baseline", lambda: None)

    assert window.export_btn.isEnabled() is False

    window.audit_running = True
    window.refresh_primary_actions()
    assert window.export_btn.isEnabled() is False

    window.audit_running = False
    report = {
        "host_os": "macOS-15",
        "meta": {"mode": "deep", "generated_at": "2026-07-04T18:33:48-05:00"},
        "background_tasks": {"items": []},
        "summary": {
            "counts": {"high": 0, "medium": 0, "low": 0},
            "overall_risk": "low",
            "top_findings": [],
            "limitations": [
                "Limited visibility: macOS denied access to 271 process connection list(s)",
                "Limited visibility: macOS denied access to 271 process socket list(s)",
            ],
            "plain_summary": [],
        },
    }

    window.audit_finished(report)

    assert window.export_btn.isEnabled() is True
    assert window.baseline.isEnabled() is True
    assert window.visibility_banner.isHidden() is False
    assert "Full Disk Access may not remove this specific limit" in window.visibility_banner_label.text()
    assert window.visibility_fix_btn.isHidden() is True
    assert window.visibility_help_btn.isHidden() is False
    assert "Jul 04, 2026 at 6:33 PM" in window.details.toPlainText()

    window.schedule_timer.stop()
    window.close()
    window.deleteLater()
    app.processEvents()
