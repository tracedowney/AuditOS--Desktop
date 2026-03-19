from __future__ import annotations

import subprocess
from typing import Any, Dict, List


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
    interfaces: List[Dict[str, Any]] = []

    try:
        output = subprocess.check_output(
            ["ifconfig"],
            text=True,
            stderr=subprocess.STDOUT,
        )
    except Exception as exc:
        return {
            "component": "network_interfaces",
            "interfaces": [],
            "findings": [
                make_finding("network", "Failed to read network interfaces", 3, {"error": str(exc)})
            ],
            "error": str(exc),
        }

    current = None

    for line in output.splitlines():

        if not line.startswith("\t") and ":" in line:
            if current:
                interfaces.append(current)

            name = line.split(":")[0]

            current = {
                "name": name,
                "addresses": [],
                "status": "unknown",
            }

        elif current:

            line = line.strip()

            if line.startswith("inet "):
                addr = line.split()[1]
                current["addresses"].append(addr)

                if addr.startswith("169.254"):
                    findings.append(
                        make_finding(
                            "network",
                            f"Link-local address detected on {current['name']} ({addr})",
                            3,
                        )
                    )

            if "status:" in line:
                current["status"] = line.split("status:")[1].strip()

    if current:
        interfaces.append(current)

    return {
        "component": "network_interfaces",
        "interfaces": interfaces,
        "findings": findings,
        "error": "",
    }
