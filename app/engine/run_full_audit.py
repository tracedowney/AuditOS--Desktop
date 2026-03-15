from __future__ import annotations

import argparse
import json
import platform
from pathlib import Path

from engine.audit_active_connections import audit_active_connections
from engine.audit_browser_extensions import audit_browser_extensions
from engine.audit_certificates import audit_certificates
from engine.audit_dns_settings import audit_dns_settings
from engine.audit_listening_ports import audit_listening_ports
from engine.audit_network_interfaces import audit_network_interfaces
from engine.audit_proxy_settings import audit_proxy_settings
from engine.audit_routes import audit_routes
from engine.audit_scheduled_tasks import audit_scheduled_tasks
from engine.audit_startup_items import audit_startup_items
from engine.summarize_findings import summarize_findings



def main() -> int:
    ap = argparse.ArgumentParser(description="System and connection security auditor")
    ap.add_argument("--output", default="full_security_audit.json")
    ap.add_argument("--pretty", action="store_true")
    args = ap.parse_args()

    report = {
        "host_os": platform.platform(),
        "browser_extensions": audit_browser_extensions(),
        "proxy_settings": audit_proxy_settings(),
        "dns_settings": audit_dns_settings(),
        "network_interfaces": audit_network_interfaces(),
        "routes": audit_routes(),
        "active_connections": audit_active_connections(),
        "listening_ports": audit_listening_ports(),
        "startup_items": audit_startup_items(),
        "scheduled_tasks": audit_scheduled_tasks(),
        "certificates": audit_certificates(),
    }

    report["summary"] = summarize_findings(report)

    out = Path(args.output)
    out.write_text(json.dumps(report, indent=2 if args.pretty else None), encoding="utf-8")

    print(f"Wrote report: {out.resolve()}")
    print(f"Overall risk: {report['summary']['overall_risk']}")
    print(f"High findings: {report['summary']['counts']['high']}")
    print(f"Medium findings: {report['summary']['counts']['medium']}")
    print(f"Low findings: {report['summary']['counts']['low']}")
    print("\nTop findings:")
    for f in report["summary"]["top_findings"][:10]:
        print(f"- [{f['severity'].upper()}] {f['detail']}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

def build_report(mode="quick"):
    report = {
        "host_os": platform.platform(),
        "browser_extensions": audit_browser_extensions(),
        "proxy_settings": audit_proxy_settings(),
        "dns_settings": audit_dns_settings(),
        "network_interfaces": audit_network_interfaces(),
        "routes": audit_routes(),
        "active_connections": audit_active_connections(),
        "listening_ports": audit_listening_ports(),
        "startup_items": audit_startup_items(),
        "scheduled_tasks": audit_scheduled_tasks(),
        "certificates": audit_certificates(),
    }

    report["summary"] = summarize_findings(report)
    return report

