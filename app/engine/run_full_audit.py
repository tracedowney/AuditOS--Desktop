from __future__ import annotations

import platform

from .audit_active_connections import audit_active_connections
from .audit_browser_extensions import audit_browser_extensions
from .audit_certificates import audit_certificates
from .audit_dns_settings import audit_dns_settings
from .audit_listening_ports import audit_listening_ports
from .audit_network_interfaces import audit_network_interfaces
from .audit_proxy_settings import audit_proxy_settings
from .audit_routes import audit_routes
from .audit_scheduled_tasks import audit_scheduled_tasks
from .audit_startup_items import audit_startup_items
from .summarize_findings import summarize_findings


def build_report(mode: str = "quick"):
    report = {
        "host_os": platform.platform(),
        "browser_extensions": audit_browser_extensions(),
        "proxy_settings": audit_proxy_settings(),
        "dns_settings": audit_dns_settings(),
        "network_interfaces": audit_network_interfaces(),
        "startup_items": audit_startup_items(),
        "scheduled_tasks": audit_scheduled_tasks(),
        "certificates": audit_certificates(),
    }

    if mode == "deep":
        report["routes"] = audit_routes()
        report["active_connections"] = audit_active_connections()
        report["listening_ports"] = audit_listening_ports()

    report["summary"] = summarize_findings(report)
    return report
