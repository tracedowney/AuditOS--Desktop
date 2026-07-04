from __future__ import annotations

import importlib


def test_macos_dns_groups_repeated_custom_servers(monkeypatch):
    module = importlib.import_module("app.engine.dns_settings.macos")
    module = importlib.reload(module)

    sample_output = """
resolver #1
  nameserver[0] : 151.236.14.64
  nameserver[1] : 203.21.66.129
resolver #2
  nameserver[0] : 151.236.14.64
  nameserver[1] : 203.21.66.129
resolver #3
  nameserver[0] : 8.8.8.8
"""

    monkeypatch.setattr(module.subprocess, "check_output", lambda *args, **kwargs: sample_output)

    report = module.run()

    findings = report["findings"]
    assert len(findings) == 2
    details = [finding["detail"] for finding in findings]
    assert "Review custom public DNS server on 2 resolver entries: 151.236.14.64" in details
    assert "Review custom public DNS server on 2 resolver entries: 203.21.66.129" in details
    assert all("8.8.8.8" not in detail for detail in details)
    assert all("explanation" in finding.get("evidence", {}) for finding in findings)
