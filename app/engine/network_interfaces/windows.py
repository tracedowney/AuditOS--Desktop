from __future__ import annotations

from typing import Any, Dict, List

from ..common_utils import make_finding, run_command


def run():
    code, stdout, stderr = run_command(["ipconfig"])
    if code != 0:
        return {
            "component": "network_interfaces",
            "interfaces": [],
            "findings": [make_finding("network", "Failed to read network interfaces", 3, {"error": stderr})],
            "error": stderr.strip(),
        }

    interfaces: List[Dict[str, Any]] = []
    findings: List[Dict[str, Any]] = []
    current: Dict[str, Any] | None = None

    for raw_line in stdout.splitlines():
        line = raw_line.rstrip()
        stripped = line.strip()

        if stripped.endswith(":") and "adapter" in stripped.lower():
            if current:
                interfaces.append(current)
            current = {"name": stripped[:-1], "addresses": [], "status": "unknown"}
            continue

        if current is None:
            continue

        if "Media State" in line and "disconnected" in line.lower():
            current["status"] = "disconnected"
        elif "IPv4 Address" in line or "Autoconfiguration IPv4 Address" in line:
            addr = stripped.split(":")[-1].replace("(Preferred)", "").strip()
            current["addresses"].append(addr)
            current["status"] = "up"
            if addr.startswith("169.254."):
                findings.append(make_finding("network", f"Link-local address detected on {current['name']} ({addr})", 3))

    if current:
        interfaces.append(current)

    return {
        "component": "network_interfaces",
        "interfaces": interfaces,
        "findings": findings,
        "error": "",
    }
