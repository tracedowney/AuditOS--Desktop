from __future__ import annotations

import re
import subprocess
from typing import Any, Dict, List


WELL_KNOWN_DNS = {
    "1.1.1.1",
    "1.0.0.1",
    "8.8.8.8",
    "8.8.4.4",
    "9.9.9.9",
    "149.112.112.112",
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
    for resolver in resolvers:
        adapters.append(
            {
                "name": resolver.get("name", ""),
                "dns_servers": resolver.get("dns_servers", []),
                "domain": resolver.get("domain", ""),
                "search_domains": resolver.get("search_domains", []),
            }
        )

        for server in resolver.get("dns_servers", []):
            if server.startswith("127.") or server == "::1":
                findings.append(
                    make_finding(
                        "dns",
                        f"Localhost DNS resolver in use on {resolver.get('name', '')}: {server}",
                        5,
                    )
                )
            elif re.match(r"^\d+\.\d+\.\d+\.\d+$", server):
                if server not in WELL_KNOWN_DNS and not server.startswith(("192.168.", "10.", "172.16.")):
                    findings.append(
                        make_finding(
                            "dns",
                            f"Review DNS server on {resolver.get('name', '')}: {server}",
                            4,
                        )
                    )

    return {
        "component": "dns_settings",
        "adapters": adapters,
        "findings": findings,
        "error": "",
    }
