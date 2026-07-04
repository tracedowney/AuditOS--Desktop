from __future__ import annotations

import re
import subprocess
from typing import Any, Dict, List


WELL_KNOWN_DNS = {
    "1.1.1.1": "Cloudflare",
    "1.0.0.1": "Cloudflare",
    "8.8.8.8": "Google Public DNS",
    "8.8.4.4": "Google Public DNS",
    "9.9.9.9": "Quad9",
    "149.112.112.112": "Quad9",
}


def make_finding(category: str, detail: str, score: int, evidence: Dict[str, Any] | None = None) -> Dict[str, Any]:
    severity = "high" if score >= 8 else "medium" if score >= 4 else "low"
    return {
        "category": category,
        "detail": detail,
        "score": score,
        "severity": severity,
        "evidence": evidence or {},
    }


def _is_private_ipv4(server: str) -> bool:
    return str(server).startswith(("192.168.", "10.", "172.16."))


def _resolver_label(names: List[str]) -> str:
    if not names:
        return "resolver entry"
    if len(names) == 1:
        return names[0]
    return f"{len(names)} resolver entries"


def _explanation_for_custom_dns(server: str, resolver_names: List[str]) -> str:
    return (
        f"{server} is a public DNS server that AuditOS does not recognize as one of its built-in familiar resolvers. "
        "That does not automatically make it unsafe, but you should know whether it belongs to your ISP, VPN, firewall, "
        f"or privacy DNS provider. Seen on {_resolver_label(resolver_names)}."
    )


def run():
    findings: List[Dict[str, Any]] = []
    resolvers: List[Dict[str, Any]] = []

    try:
        output = subprocess.check_output(
            ["scutil", "--dns"],
            text=True,
            stderr=subprocess.STDOUT,
        )
    except Exception as exc:
        return {
            "component": "dns_settings",
            "adapters": [],
            "findings": [
                make_finding("dns", "Failed to read macOS DNS settings", 3, {"error": str(exc)})
            ],
            "error": str(exc),
        }

    current: Dict[str, Any] | None = None

    for raw_line in output.splitlines():
        line = raw_line.strip()

        if line.startswith("resolver #"):
            if current:
                resolvers.append(current)
            current = {
                "name": line,
                "dns_servers": [],
                "domain": "",
                "search_domains": [],
            }
            continue

        if current is None:
            continue

        if line.startswith("domain") and ":" in line:
            current["domain"] = line.split(":", 1)[1].strip()
        elif line.startswith("search domain") and ":" in line:
            current["search_domains"].append(line.split(":", 1)[1].strip())
        elif line.startswith("nameserver[") and ":" in line:
            server = line.split(":", 1)[1].strip()
            current["dns_servers"].append(server)

    if current:
        resolvers.append(current)

    adapters = []
    server_to_resolvers: Dict[str, List[str]] = {}
    for resolver in resolvers:
        resolver_name = str(resolver.get("name", "")).strip()
        unique_servers: List[str] = []
        for server in resolver.get("dns_servers", []):
            if server not in unique_servers:
                unique_servers.append(server)
                server_to_resolvers.setdefault(server, []).append(resolver_name)

        adapters.append(
            {
                "name": resolver_name,
                "dns_servers": unique_servers,
                "domain": resolver.get("domain", ""),
                "search_domains": resolver.get("search_domains", []),
            }
        )

    for server, resolver_names in server_to_resolvers.items():
        if server.startswith("127.") or server == "::1":
            findings.append(
                make_finding(
                    "dns",
                    f"Localhost DNS resolver in use on {_resolver_label(resolver_names)}: {server}",
                    5,
                    {
                        "explanation": (
                            f"{server} points DNS lookups back to this Mac. That can be normal when another local app handles DNS filtering, "
                            f"VPN routing, or encrypted DNS. Seen on {_resolver_label(resolver_names)}."
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
                    f"Review custom public DNS server on {_resolver_label(resolver_names)}: {server}",
                    4,
                    {
                        "explanation": _explanation_for_custom_dns(server, resolver_names),
                    },
                )
            )

    return {
        "component": "dns_settings",
        "adapters": adapters,
        "findings": findings,
        "error": "",
    }
