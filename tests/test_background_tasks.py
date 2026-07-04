from __future__ import annotations

import importlib


class _FakeProcess:
    def __init__(
        self,
        pid: int,
        name: str,
        exe: str,
        cmdline: list[str],
        status: str = "sleeping",
        username: str = "user",
        ppid: int | None = None,
    ):
        self.pid = pid
        self.info = {
            "pid": pid,
            "ppid": ppid,
            "name": name,
            "exe": exe,
            "cmdline": cmdline,
            "status": status,
            "username": username,
        }


def test_background_tasks_flags_core_name_in_unexpected_path(monkeypatch):
    module = importlib.import_module("app.engine.audit_background_tasks")
    module = importlib.reload(module)

    monkeypatch.setattr(
        module.psutil,
        "process_iter",
        lambda attrs=None: [
            _FakeProcess(
                101,
                "svchost.exe",
                r"C:\Users\alice\Downloads\svchost.exe",
                [r"C:\Users\alice\Downloads\svchost.exe"],
            )
        ],
    )

    report = module.audit_background_tasks()

    assert report["component"] == "background_tasks"
    assert len(report["items"]) == 1
    assert report["findings"]
    finding = report["findings"][0]
    assert finding["severity"] == "high"
    assert "core system process" in finding["detail"]
    assert "impact_hint" in finding["evidence"]


def test_background_tasks_explains_script_host(monkeypatch):
    module = importlib.import_module("app.engine.audit_background_tasks")
    module = importlib.reload(module)

    monkeypatch.setattr(
        module.psutil,
        "process_iter",
        lambda attrs=None: [
            _FakeProcess(
                202,
                "powershell.exe",
                r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                [
                    r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                    "-NoProfile",
                    "-EncodedCommand",
                    "SQBtAHAAbwByAHQAYQBuAHQAA==",
                ],
            )
        ],
    )

    report = module.audit_background_tasks()

    assert len(report["items"]) == 1
    item = report["items"][0]
    assert item["role"] == "script_host"
    assert "can run commands or scripts" in item["explanation"]
    assert report["findings"]
    assert "command line looks unusually powerful or remote-driven" in report["findings"][0]["detail"]


def test_background_tasks_recognizes_auditos_helper_commands(monkeypatch):
    module = importlib.import_module("app.engine.audit_background_tasks")
    module = importlib.reload(module)

    monkeypatch.setattr(
        module.psutil,
        "process_iter",
        lambda attrs=None: [
            _FakeProcess(
                301,
                "bash",
                "/bin/bash",
                [
                    "/bin/bash",
                    "-lc",
                    'cd /Users/test/AuditOS--Desktop && PYTHONPATH="/Users/test/AuditOS--Desktop:/Users/test/AuditOS--Desktop/app" ./venv/bin/python -m pytest tests/test_background_tasks.py',
                ],
            )
        ],
    )

    report = module.audit_background_tasks()

    assert len(report["items"]) == 1
    item = report["items"][0]
    assert item["role"] == "auditos_helper"
    assert item["review_label"] == "Recognized AuditOS task"
    assert "AuditOS project" in item["explanation"]
    assert "running AuditOS tests" in item["command_summary"]
    assert not report["findings"]


def test_background_tasks_recognizes_auditos_app(monkeypatch):
    module = importlib.import_module("app.engine.audit_background_tasks")
    module = importlib.reload(module)

    monkeypatch.setattr(
        module.psutil,
        "process_iter",
        lambda attrs=None: [
            _FakeProcess(
                401,
                "AuditOS",
                "/private/var/folders/x/AppTranslocation/ABC/d/AuditOS.app/Contents/MacOS/AuditOS",
                ["/private/var/folders/x/AppTranslocation/ABC/d/AuditOS.app/Contents/MacOS/AuditOS"],
            )
        ],
    )

    report = module.audit_background_tasks()

    item = report["items"][0]
    assert item["role"] == "auditos_app"
    assert item["role_label"] == "AuditOS app"
    assert item["review_label"] == "Recognized AuditOS task"
    assert "App Translocation path" in item["explanation"]
