from __future__ import annotations

import importlib
from types import SimpleNamespace


def test_parse_macos_netstat_line_handles_process_names_with_spaces():
    module = importlib.import_module("app.engine.live_network_collectors")
    module = importlib.reload(module)

    parsed = module._parse_macos_netstat_line(
        "tcp4       0      0  10.14.0.2.62007        104.18.37.228.443      ESTABLISHED         5548         4572  131072  131472  Codex (Service):19111  00102 00000008 00000000002ffc8e 00000080 04000900      2      0 000000"
    )

    assert parsed == (
        "tcp4",
        "10.14.0.2.62007",
        "104.18.37.228.443",
        "ESTABLISHED",
        "Codex (Service)",
        19111,
    )


def test_collect_macos_tcp_snapshot_builds_active_and_listening_items(monkeypatch):
    module = importlib.import_module("app.engine.live_network_collectors")
    module = importlib.reload(module)

    output = "\n".join(
        [
            "Active Internet connections (including servers)",
            "Proto Recv-Q Send-Q  Local Address                                 Foreign Address                               (state)          rxbytes      txbytes  rhiwat  shiwat          process:pid    state  options           gencnt    flags   flags1 usecnt rtncnt fltrs",
            "tcp4       0      0  10.14.0.2.61394        74.125.201.188.5228    ESTABLISHED        14360         2173  131072  131472  Codex (Service):19111  00102 00000008 00000000002ecc57 00000080 04000900      2      0 000000",
            "tcp4       0      0  *.445                  *.*                    LISTEN                 0            0  131072  131072          launchd:1      00180 00000006 0000000000000953 00000000 00000800      1      0 000000",
        ]
    )

    monkeypatch.setattr(
        module.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(returncode=0, stdout=output, stderr=""),
    )

    class FakeProcess:
        def __init__(self, pid: int):
            self.pid = pid

        def name(self):
            return {19111: "Codex (Service)", 1: "launchd"}[self.pid]

        def exe(self):
            return {
                19111: "/Applications/Codex.app/Contents/MacOS/Codex",
                1: "/sbin/launchd",
            }[self.pid]

    monkeypatch.setattr(module.psutil, "Process", FakeProcess)

    snapshot = module._collect_macos_tcp_snapshot()

    assert snapshot["hidden_active"] == 0
    assert snapshot["hidden_listening"] == 0
    assert snapshot["active_connections"] == [
        {
            "pid": 19111,
            "name": "Codex (Service)",
            "exe": "/Applications/Codex.app/Contents/MacOS/Codex",
            "local_addr": "10.14.0.2",
            "local_port": 61394,
            "remote_addr": "74.125.201.188",
            "remote_port": 5228,
            "status": "ESTABLISHED",
        }
    ]
    assert snapshot["listening_ports"] == [
        {
            "pid": 1,
            "name": "launchd",
            "exe": "/sbin/launchd",
            "local_addr": "0.0.0.0",
            "local_port": 445,
        }
    ]
