from __future__ import annotations

import argparse
import json
import re
from typing import Any, Dict, List

from .common_utils import make_finding, run_command

VPN_HINTS = ["vpn", "wireguard", "openvpn", "tun", "tap", "nord", "tailscale", "zerotier"]


def _extract_ipv4(text: str) -> List[str]:
    return re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text)


def _extract_ipv6(text: str) -> List[str]:
    values = []
    for token in re.findall(r"\b[0-9A-Fa-f:]{2,}\b", text):
        if ":" in token and token.lower() != "fe80":
            values.append(token)
    return values


def audit_network_interfaces() -> Dict[str, Any]:
    code, stdout, stderr = run_command(["ipconfig", "/all"])
    adapters: List[Dict[str, Any]] = []
    findings = []
    current = None
    pending_key = None

    for raw_line in stdout.splitlines():
        line = raw_line.rstrip()
        stripped = line.strip()

        if not stripped:
            pending_key = None
            continue

        if line and not raw_line.startswith((" ", "\t")):
            if stripped.endswith(":"):
                current = {
                    "name": stripped[:-1],
                    "ipv4": [],
                    "ipv6": [],
                    "gateways": [],
                }
                adapters.append(current)
                pending_key = None
            continue

        if current is None:
            continue

        if "IPv4 Address" in stripped:
            vals = _extract_ipv4(stripped)
            if vals:
                current["ipv4"].extend(vals)
                pending_key = None
            else:
                pending_key = "ipv4"
            continue

        if "IPv6 Address" in stripped or "Temporary IPv6 Address" in stripped or "Link-local IPv6 Address" in stripped:
            vals = _extract_ipv6(stripped)
            if vals:
                current["ipv6"].extend(vals)
                pending_key = None
            else:
                pending_key = "ipv6"
            continue

        if "Default Gateway" in stripped:
            vals = _extract_ipv4(stripped) + _extract_ipv6(stripped)
            if vals:
                current["gateways"].extend(vals)
                pending_key = None
            else:
                pending_key = "gateways"
            continue

        if pending_key:
            if pending_key == "ipv4":
                vals = _extract_ipv4(stripped)
            elif pending_key == "ipv6":
                vals = _extract_ipv6(stripped)
            else:
                vals = _extract_ipv4(stripped) + _extract_ipv6(stripped)

            if vals:
                current[pending_key].extend(vals)
                pending_key = None
            else:
                pending_key = None

    for adapter in adapters:
        adapter["ipv4"] = sorted(set(adapter["ipv4"]))
        adapter["ipv6"] = sorted(set(adapter["ipv6"]))
        adapter["gateways"] = sorted(set(adapter["gateways"]))

    gateway_count = sum(1 for a in adapters if a["gateways"])
    if gateway_count > 1:
        findings.append(
            make_finding(
                "network_interfaces",
                "Multiple interfaces have default gateways",
                4,
                {"gateway_count": gateway_count},
            )
        )

    for adapter in adapters:
        if any(h in adapter["name"].lower() for h in VPN_HINTS):
            findings.append(
                make_finding(
                    "network_interfaces",
                    f"VPN-like interface present: {adapter['name']}",
                    1,
                )
            )

    if code != 0:
        findings.append(
            make_finding(
                "network_interfaces",
                "Failed to read interface configuration",
                3,
                {"error": stderr},
            )
        )

    return {
        "component": "network_interfaces",
        "adapters": adapters,
        "findings": findings,
        "error": stderr.strip(),
    }


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--pretty", action="store_true")
    args = ap.parse_args()
    print(json.dumps(audit_network_interfaces(), indent=2 if args.pretty else None))