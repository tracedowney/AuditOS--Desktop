from __future__ import annotations

import importlib


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


def test_first_run_notice_only_honors_user_data_ack(monkeypatch, tmp_path):
    module = importlib.import_module("app.services.first_run_notice")
    module = importlib.reload(module)
    module.ACK_FILE = tmp_path / "terms_acknowledged.json"

    legacy_ack = module.APP_DIR / "data" / "terms_acknowledged.json"
    original = legacy_ack.read_text(encoding="utf-8") if legacy_ack.exists() else None
    legacy_ack.parent.mkdir(parents=True, exist_ok=True)
    legacy_ack.write_text('{"accepted": true}', encoding="utf-8")

    try:
        assert module.acknowledged() is False
        module.save_ack()
        assert module.acknowledged() is True
    finally:
        if original is None:
            legacy_ack.unlink(missing_ok=True)
        else:
            legacy_ack.write_text(original, encoding="utf-8")
