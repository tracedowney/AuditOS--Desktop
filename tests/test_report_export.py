from __future__ import annotations

from app.services.report_export import default_report_filename


def test_default_report_filename_uses_mode_and_run_timestamp():
    report = {
        "meta": {
            "mode": "deep",
            "generated_at": "2026-06-12T04:28:15-05:00",
        }
    }

    assert default_report_filename(report) == "AuditOS_Deep_Audit_20260612_042815.json"


def test_default_report_filename_falls_back_when_metadata_missing():
    name = default_report_filename({})

    assert name.startswith("AuditOS_Audit_")
    assert name.endswith(".json")
