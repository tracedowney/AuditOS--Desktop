from __future__ import annotations

import re
from typing import Any, Dict, List

from ..common_utils import make_finding, run_command


WELL_KNOWN_DNS = {
    "1.1.1.1",
    "1.0.0.1",
    "8.8.8.8",
    "8.8.4.4",
    "9.9.9.9",
    "149.112.112.112",
}


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

    for adapter in adapters:
        servers = []
        for server in adapter.get("dns_servers", []):
            if server not in servers:
                servers.append(server)
        adapter["dns_servers"] = servers

        for server in servers:
            if server.startswith("127.") or server == "::1":
                findings.append(make_finding("dns", f"Localhost DNS resolver in use on {adapter['name']}: {server}", 5))
            elif re.match(r"^\d+\.\d+\.\d+\.\d+$", server):
                if server not in WELL_KNOWN_DNS and not server.startswith(("192.168.", "10.", "172.16.")):
                    findings.append(make_finding("dns", f"Review DNS server on {adapter['name']}: {server}", 4))

    return {
        "component": "dns_settings",
        "adapters": adapters,
        "findings": findings,
        "error": "",
    }
