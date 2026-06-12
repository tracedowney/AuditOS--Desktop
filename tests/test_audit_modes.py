from __future__ import annotations

import importlib
from datetime import datetime


def _empty_component(name: str) -> dict:
    return {"component": name, "findings": []}


def test_quick_audit_skips_deep_collectors(monkeypatch):
    module = importlib.import_module("app.engine.run_full_audit")
    module = importlib.reload(module)

    monkeypatch.setattr(module, "audit_browser_extensions", lambda: _empty_component("browser_extensions"))
    monkeypatch.setattr(module, "audit_proxy_settings", lambda: _empty_component("proxy_settings"))
    monkeypatch.setattr(module, "audit_dns_settings", lambda: _empty_component("dns_settings"))
    monkeypatch.setattr(module, "audit_network_interfaces", lambda: _empty_component("network_interfaces"))
    monkeypatch.setattr(module, "audit_startup_items", lambda: _empty_component("startup_items"))
    monkeypatch.setattr(module, "audit_scheduled_tasks", lambda: _empty_component("scheduled_tasks"))
    monkeypatch.setattr(module, "audit_certificates", lambda: _empty_component("certificates"))
    monkeypatch.setattr(module, "audit_routes", lambda: (_ for _ in ()).throw(AssertionError("routes should not run")))
    monkeypatch.setattr(module, "audit_active_connections", lambda: (_ for _ in ()).throw(AssertionError("active connections should not run")))
    monkeypatch.setattr(module, "audit_listening_ports", lambda: (_ for _ in ()).throw(AssertionError("listening ports should not run")))
    monkeypatch.setattr(
        module,
        "summarize_findings",
        lambda report: {
            "counts": {"high": 0, "medium": 0, "low": 0},
            "overall_risk": "low",
            "top_findings": [],
            "limitations": [],
            "plain_summary": [],
            "seen_keys": sorted(report.keys()),
        },
    )

    report = module.build_report(mode="quick")

    assert "routes" not in report
    assert "active_connections" not in report
    assert "listening_ports" not in report
    assert report["summary"]["seen_keys"] == [
        "browser_extensions",
        "certificates",
        "dns_settings",
        "host_os",
        "meta",
        "network_interfaces",
        "proxy_settings",
        "scheduled_tasks",
        "startup_items",
    ]
    assert report["meta"]["mode"] == "quick"
    assert datetime.fromisoformat(report["meta"]["generated_at"])


def test_deep_audit_includes_deep_collectors(monkeypatch):
    module = importlib.import_module("app.engine.run_full_audit")
    module = importlib.reload(module)
    calls: list[str] = []

    def recorder(name: str):
        def _record():
            calls.append(name)
            return _empty_component(name)

        return _record

    monkeypatch.setattr(module, "audit_browser_extensions", recorder("browser_extensions"))
    monkeypatch.setattr(module, "audit_proxy_settings", recorder("proxy_settings"))
    monkeypatch.setattr(module, "audit_dns_settings", recorder("dns_settings"))
    monkeypatch.setattr(module, "audit_network_interfaces", recorder("network_interfaces"))
    monkeypatch.setattr(module, "audit_startup_items", recorder("startup_items"))
    monkeypatch.setattr(module, "audit_scheduled_tasks", recorder("scheduled_tasks"))
    monkeypatch.setattr(module, "audit_certificates", recorder("certificates"))
    monkeypatch.setattr(module, "audit_routes", recorder("routes"))
    monkeypatch.setattr(module, "audit_active_connections", recorder("active_connections"))
    monkeypatch.setattr(module, "audit_listening_ports", recorder("listening_ports"))
    monkeypatch.setattr(
        module,
        "summarize_findings",
        lambda report: {
            "counts": {"high": 0, "medium": 0, "low": 0},
            "overall_risk": "low",
            "top_findings": [],
            "limitations": [],
            "plain_summary": [],
        },
    )

    report = module.build_report(mode="deep")

    assert "routes" in report
    assert "active_connections" in report
    assert "listening_ports" in report
    assert report["meta"]["mode"] == "deep"
    assert datetime.fromisoformat(report["meta"]["generated_at"])
    assert calls == [
        "browser_extensions",
        "proxy_settings",
        "dns_settings",
        "network_interfaces",
        "startup_items",
        "scheduled_tasks",
        "certificates",
        "routes",
        "active_connections",
        "listening_ports",
    ]
