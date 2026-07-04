from __future__ import annotations

import importlib
import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication

from services.update_checker import ReleaseInfo, check_for_updates, select_target_release


def _app() -> QApplication:
    return QApplication.instance() or QApplication([])


def _release(
    tag_name: str,
    *,
    prerelease: bool,
    draft: bool = False,
    published_at: str = "2026-07-01T00:00:00Z",
) -> ReleaseInfo:
    return ReleaseInfo(
        tag_name=tag_name,
        name=tag_name,
        html_url=f"https://example.test/{tag_name}",
        prerelease=prerelease,
        draft=draft,
        published_at=published_at,
    )


def test_beta_users_get_newer_beta_when_available():
    releases = [
        _release("v0.4.6-beta", prerelease=True, published_at="2026-07-01T00:00:00Z"),
        _release("v0.4.7-beta", prerelease=True, published_at="2026-07-02T00:00:00Z"),
        _release("v0.5.0", prerelease=False, published_at="2026-07-03T00:00:00Z"),
    ]

    target = select_target_release(releases, "0.4.6-beta")
    result = check_for_updates("0.4.6-beta", fetcher=lambda: releases)

    assert target is not None
    assert target.version == "0.4.7-beta"
    assert result.status == "update_available"
    assert result.release is not None
    assert result.release.version == "0.4.7-beta"


def test_beta_users_fall_forward_to_newer_stable_when_no_newer_beta_exists():
    releases = [
        _release("v0.4.6-beta", prerelease=True, published_at="2026-07-01T00:00:00Z"),
        _release("v0.4.6", prerelease=False, published_at="2026-07-04T00:00:00Z"),
    ]

    result = check_for_updates("0.4.6-beta", fetcher=lambda: releases)

    assert result.status == "update_available"
    assert result.release is not None
    assert result.release.version == "0.4.6"


def test_stable_users_ignore_newer_beta_and_stay_on_stable_channel():
    releases = [
        _release("v0.5.1-beta", prerelease=True, published_at="2026-07-02T00:00:00Z"),
        _release("v0.5.0", prerelease=False, published_at="2026-07-01T00:00:00Z"),
    ]

    result = check_for_updates("0.5.0", fetcher=lambda: releases)

    assert result.status == "up_to_date"
    assert result.release is not None
    assert result.release.version == "0.5.0"


def test_update_check_handles_empty_release_feed():
    result = check_for_updates("0.4.6-beta", fetcher=lambda: [])

    assert result.status == "no_releases"
    assert result.release is None
    assert "published beta releases" in result.message


def test_main_window_routes_update_check_results_through_the_new_button(monkeypatch):
    module = importlib.import_module("ui.main_window")
    module = importlib.reload(module)

    fake_result = check_for_updates(
        "0.4.6-beta",
        fetcher=lambda: [_release("v0.4.6-beta", prerelease=True)],
    )
    captured: list[object] = []

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
    monkeypatch.setattr(module, "perform_update_check", lambda version: fake_result)
    monkeypatch.setattr(module.MainWindow, "handle_update_check_result", lambda self, result: captured.append(result))

    app = _app()
    window = module.MainWindow()

    assert window.update_btn.text() == "Check for Updates"

    window.update_btn.click()

    assert captured == [fake_result]

    window.schedule_timer.stop()
    window.close()
    window.deleteLater()
    app.processEvents()
