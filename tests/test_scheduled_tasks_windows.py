from __future__ import annotations

import importlib


def test_windows_scheduled_tasks_ignores_literal_csv_header_row(monkeypatch):
    module = importlib.import_module("app.engine.scheduled_tasks.windows")
    module = importlib.reload(module)

    stdout = "\n".join([
        '"HostName","TaskName","Next Run Time","Status","Logon Mode","Last Run Time","Last Result","Author","Task To Run"',
        '"COMPUTER","TaskName","N/A","Status","Interactive/Background","N/A","0","Author","Task To Run"',
        '"COMPUTER","\\\\Microsoft\\\\Windows\\\\Hotpatch\\\\Monitoring","N/A","Ready","Interactive/Background","N/A","0","N/A","%systemroot%\\\\system32\\\\cmd.exe /d /c %systemroot%\\\\system32\\\\hpatchmonTask.cmd"',
    ])

    monkeypatch.setattr(module, "run_command", lambda args: (0, stdout, ""))

    report = module.run()

    assert [item["task_name"] for item in report["items"]] == [
        "\\\\Microsoft\\\\Windows\\\\Hotpatch\\\\Monitoring"
    ]
    assert len(report["findings"]) == 1
