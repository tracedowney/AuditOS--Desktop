from __future__ import annotations

import argparse
import json
import re

from .common_utils import make_finding, run_command

WELL_KNOWN_DNS = {"1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9", "149.112.112.112"}


def audit_dns_settings():
    code, stdout, stderr = run_command(["ipconfig", "/all"])
    adapters = []
    findings = []

    current = None
    collecting = False

    for raw_line in stdout.splitlines():
        line = raw_line.rstrip()
        if line and not line.startswith(" "):
            collecting = False
            if ":" in line:
                current = {"name": line.strip(" :"), "dns_servers": []}
                adapters.append(current)
            continue

        if current is None:
            continue

        if "DNS Servers" in line:
            collecting = True
            maybe = line.split(":", 1)[-1].strip()
            if maybe:
                current["dns_servers"].append(maybe)
            continue

        if collecting:
            stripped = line.strip()
            if stripped and re.match(r"^[0-9a-fA-F\.:]+$", stripped):
                current["dns_servers"].append(stripped)
            else:
                collecting = False

    for adapter in adapters:
        for server in adapter["dns_servers"]:
            if server.startswith("127.") or server == "::1":
                findings.append(make_finding("dns", f"Localhost DNS resolver in use on {adapter['name']}: {server}", 5))
            elif re.match(r"^\d+\.\d+\.\d+\.\d+$", server) and server not in WELL_KNOWN_DNS and not server.startswith(("192.168.", "10.", "172.16.")):
                findings.append(make_finding("dns", f"Review DNS server on {adapter['name']}: {server}", 4))

    if code != 0:
        findings.append(make_finding("dns", "Failed to read DNS settings", 3, {"error": stderr}))

    return {
        "component": "dns_settings",
        "adapters": adapters,
        "findings": findings,
        "error": stderr.strip(),
    }


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--pretty", action="store_true")
    args = ap.parse_args()
    print(json.dumps(audit_dns_settings(), indent=2 if args.pretty else None))