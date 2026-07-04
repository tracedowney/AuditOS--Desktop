from __future__ import annotations

import re
from typing import Any, Dict, List

from ..common_utils import make_finding, run_command


WELL_KNOWN_DNS = {
    "1.1.1.1": "Cloudflare",
    "1.0.0.1": "Cloudflare",
    "8.8.8.8": "Google Public DNS",
    "8.8.4.4": "Google Public DNS",
    "9.9.9.9": "Quad9",
    "149.112.112.112": "Quad9",
}


def _is_private_ipv4(server: str) -> bool:
    return str(server).startswith(("192.168.", "10.", "172.16."))


def _adapter_label(names: list[str]) -> str:
    if not names:
        return "adapter entry"
    if len(names) == 1:
        return names[0]
    return f"{len(names)} adapter entries"


def _explanation_for_custom_dns(server: str, adapter_names: list[str]) -> str:
    return (
        f"{server} is a public DNS server that AuditOS does not recognize as one of its built-in familiar resolvers. "
        "That does not automatically make it unsafe, but you should know whether it belongs to your ISP, VPN, firewall, "
        f"or privacy DNS provider. Seen on {_adapter_label(adapter_names)}."
    )


def run():
    code, stdout, stderr = run_command(["ipconfig", "/all"])
    if code != 0:
        return {
            "component": "dns_settings",
            "adapters": [],
            "findings": [make_finding("dns", "Failed to read Windows DNS settings", 3, {"error": stderr})],
            "error": stderr.strip(),
        }

    adapters: List[Dict[str, Any]] = []
    findings: List[Dict[str, Any]] = []
    current: Dict[str, Any] | None = None
    dns_indent = None

    for raw_line in stdout.splitlines():
        line = raw_line.rstrip()
        stripped = line.strip()

        if stripped.endswith(":") and "adapter" in stripped.lower():
            if current:
                adapters.append(current)
            current = {"name": stripped[:-1], "dns_servers": []}
            dns_indent = None
            continue

        if current is None:
            continue

        match = re.match(r"^(?P<indent>\s*)DNS Servers[ .:]+(?P<value>.+)$", line)
        if match:
            dns_indent = len(match.group("indent"))
            current["dns_servers"].append(match.group("value").strip())
            continue

        if dns_indent is not None:
            indent = len(line) - len(line.lstrip())
            if indent > dns_indent and stripped and re.match(r"^[0-9a-fA-F:.]+$", stripped):
                current["dns_servers"].append(stripped)
                continue
            dns_indent = None

    if current:
        adapters.append(current)

    server_to_adapters: Dict[str, list[str]] = {}
    for adapter in adapters:
        servers = []
        for server in adapter.get("dns_servers", []):
            if server not in servers:
                servers.append(server)
                server_to_adapters.setdefault(server, []).append(str(adapter["name"]))
        adapter["dns_servers"] = servers

    for server, adapter_names in server_to_adapters.items():
        if server.startswith("127.") or server == "::1":
            findings.append(
                make_finding(
                    "dns",
                    f"Localhost DNS resolver in use on {_adapter_label(adapter_names)}: {server}",
                    5,
                    {
                        "explanation": (
                            f"{server} points DNS lookups back to this PC. That can be normal when another local app handles DNS filtering, "
                            f"VPN routing, or encrypted DNS. Seen on {_adapter_label(adapter_names)}."
                        )
                    },
                )
            )
            continue
        if re.match(r"^\d+\.\d+\.\d+\.\d+$", server):
            if server in WELL_KNOWN_DNS or _is_private_ipv4(server):
                continue
            findings.append(
                make_finding(
                    "dns",
                    f"Review custom public DNS server on {_adapter_label(adapter_names)}: {server}",
                    4,
                    {
                        "explanation": _explanation_for_custom_dns(server, adapter_names),
                    },
                )
            )

    return {
        "component": "dns_settings",
        "adapters": adapters,
        "findings": findings,
        "error": "",
    }
