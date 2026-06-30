from __future__ import annotations

import importlib
import json


def test_baseline_store_does_not_fall_back_to_legacy_repo_state(monkeypatch, tmp_path):
    module = importlib.import_module("app.services.baseline_store")
    module = importlib.reload(module)
    module.BASELINE_PATH = tmp_path / "baseline.json"
    module.LAST_REPORT_PATH = tmp_path / "last_report.json"
    module.SETTINGS_PATH = tmp_path / "settings.json"

    legacy_path = module.APP_DIR / "data" / "baseline.json"
    original = legacy_path.read_text(encoding="utf-8") if legacy_path.exists() else None
    legacy_path.parent.mkdir(parents=True, exist_ok=True)
    legacy_path.write_text('{"report": {"legacy": true}}', encoding="utf-8")

    try:
        assert module.load_baseline() is None
    finally:
        if original is None:
            legacy_path.unlink(missing_ok=True)
        else:
            legacy_path.write_text(original, encoding="utf-8")


def test_baseline_store_only_honors_current_version_payloads(monkeypatch, tmp_path):
    module = importlib.import_module("app.services.baseline_store")
    module = importlib.reload(module)
    module.BASELINE_PATH = tmp_path / "baseline.json"
    module.LAST_REPORT_PATH = tmp_path / "last_report.json"
    module.SETTINGS_PATH = tmp_path / "settings.json"

    stale_payload = {
        "saved_at": "2026-01-01T00:00:00Z",
        "app_version": "0.4.2-beta",
        "data_version": "0.4.2-beta",
        "report": {"legacy": True},
    }
    module.BASELINE_PATH.write_text(json.dumps(stale_payload), encoding="utf-8")
    module.LAST_REPORT_PATH.write_text(json.dumps(stale_payload), encoding="utf-8")

    assert module.load_baseline() is None
    assert module.load_last_report() is None

    current_report = {"summary": {"overall_risk": "low"}}
    module.save_baseline(current_report)
    module.save_last_report(current_report)

    loaded_baseline = module.load_baseline()
    loaded_last_report = module.load_last_report()

    assert loaded_baseline is not None
    assert loaded_baseline["report"] == current_report
    assert loaded_baseline["app_version"] == module.APP_VERSION
    assert loaded_baseline["data_version"] == module.PERSISTENCE_VERSION

    assert loaded_last_report is not None
    assert loaded_last_report["report"] == current_report


def test_load_settings_merges_new_schedule_defaults(tmp_path):
    module = importlib.import_module("app.services.baseline_store")
    module = importlib.reload(module)
    module.BASELINE_PATH = tmp_path / "baseline.json"
    module.LAST_REPORT_PATH = tmp_path / "last_report.json"
    module.SETTINGS_PATH = tmp_path / "settings.json"

    module.SETTINGS_PATH.write_text(json.dumps({
        "schedule_enabled": True,
        "schedule_frequency": "monthly",
        "schedule_mode": "deep",
        "ai_enabled": True,
        "license_tier": "free",
    }), encoding="utf-8")

    settings = module.load_settings()

    assert settings["schedule_enabled"] is True
    assert settings["schedule_frequency"] == "monthly"
    assert settings["schedule_mode"] == "deep"
    assert settings["schedule_last_run_at"] is None
    assert settings["schedule_next_run_at"] is None
    assert settings["ai_enabled"] is True


def test_first_run_notice_only_honors_current_notice_version(monkeypatch, tmp_path):
    module = importlib.import_module("app.services.first_run_notice")
    module = importlib.reload(module)
    module.ACK_FILE = tmp_path / "terms_acknowledged.json"

    legacy_ack = module.APP_DIR / "data" / "terms_acknowledged.json"
    original = legacy_ack.read_text(encoding="utf-8") if legacy_ack.exists() else None
    legacy_ack.parent.mkdir(parents=True, exist_ok=True)
    legacy_ack.write_text('{"accepted": true}', encoding="utf-8")

    try:
        assert module.acknowledged() is False

        module.ACK_FILE.write_text(json.dumps({
            "accepted": True,
            "app_version": "0.4.2-beta",
            "notice_version": "0.4.2-beta",
        }), encoding="utf-8")
        assert module.acknowledged() is False

        module.save_ack()
        assert module.acknowledged() is True
    finally:
        if original is None:
            legacy_ack.unlink(missing_ok=True)
        else:
            legacy_ack.write_text(original, encoding="utf-8")


def test_behavior_snapshot_only_honors_current_version(monkeypatch, tmp_path):
    module = importlib.import_module("app.services.network_behavior_baseline")
    module = importlib.reload(module)
    module.HISTORY_DIR = tmp_path / "history"
    module.HISTORY_DIR.mkdir(parents=True, exist_ok=True)
    module.LEGACY_HISTORY_DIR = tmp_path / "legacy"
    module.LEGACY_HISTORY_DIR.mkdir(parents=True, exist_ok=True)

    stale_snapshot = {
        "saved_at": "2026-01-01T00:00:00Z",
        "app_version": "0.4.2-beta",
        "data_version": "0.4.2-beta",
        "connections": [],
        "listening_ports": [],
        "extensions": [],
        "dns_servers": [],
        "startup_items": [],
        "scheduled_tasks": [],
    }
    (module.HISTORY_DIR / "20260101T000000Z.json").write_text(json.dumps(stale_snapshot), encoding="utf-8")

    assert module.load_latest_snapshot() is None

    report = {
        "active_connections": {"items": []},
        "listening_ports": {"items": []},
        "browser_extensions": {"items": []},
        "dns_settings": {"adapters": []},
        "startup_items": {"items": []},
        "scheduled_tasks": {"items": []},
    }
    module.save_snapshot(report)

    loaded = module.load_latest_snapshot()
    assert loaded is not None
    assert loaded["app_version"] == module.APP_VERSION
    assert loaded["data_version"] == module.PERSISTENCE_VERSION
