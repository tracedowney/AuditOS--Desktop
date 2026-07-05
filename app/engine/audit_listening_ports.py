from __future__ import annotations

from typing import Any, Dict, List

from engine.live_network_collectors import collect_listening_port_items

WINDOWS_CORE_PROCESSES = {"svchost.exe", "lsass.exe", "wininit.exe", "services.exe", "system", "spoolsv.exe"}
SAFE_WINDOWS_PORTS = {135, 139, 445, 2869, 3389, 5040, 5355, 5357, 5358, 5985, 5986, 7680}
RPC_DYNAMIC_PORT_RANGE = range(49152, 65536)

MACOS_COMMON_SERVICES = {
    "controlcenter",
    "rapportd",
    "sharingd",
    "mDNSResponder",
    "trustd",
    "cfnetworkagent",
    "launchd",
    "kdc",
}

FRIENDLY_PROCESS_NAMES = {
    "lsass.exe": "Windows security service",
    "services.exe": "Windows services manager",
    "spoolsv.exe": "Windows print spooler",
    "svchost.exe": "Windows service host",
    "system": "Windows System",
    "wininit.exe": "Windows startup service",
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


def suspicious_path(path: str) -> bool:
    p = (path or "").lower()
    return any(x in p for x in ["/tmp/", "/downloads/", "/desktop/", "/private/tmp/"])


def _friendly_name(name: str) -> str:
    normalized = str(name).strip().lower()
    return FRIENDLY_PROCESS_NAMES.get(normalized, name)


def audit_listening_ports() -> Dict[str, Any]:
    items, limitations = collect_listening_port_items()
    findings: List[Dict[str, Any]] = []

    seen = set()
    seen_findings = set()
    for item in items:
        pid = int(item.get("pid", 0))
        name = str(item.get("name", ""))
        exe = str(item.get("exe", ""))
        local_ip = str(item.get("local_addr", ""))
        local_port = int(item.get("local_port", 0))

        key = (pid, local_ip, local_port)
        if key in seen:
            continue
        seen.add(key)

        low_name = name.lower()

        if suspicious_path(exe) and local_ip not in ("127.0.0.1", "::1", ""):
            findings.append(
                make_finding("listening_ports", f"Process in review-worthy path listening publicly: {name}", 8, item)
            )
            continue

        if low_name in WINDOWS_CORE_PROCESSES:
            if local_port in SAFE_WINDOWS_PORTS:
                continue
            if local_port in RPC_DYNAMIC_PORT_RANGE:
                finding_key = ("windows_core_rpc", low_name, local_port)
                if finding_key not in seen_findings:
                    seen_findings.add(finding_key)
                    findings.append(
                        make_finding(
                            "listening_ports",
                            f"Likely normal Windows background service: {_friendly_name(name)} is waiting for internal Windows communication on port {local_port}",
                            1,
                            item,
                        )
                    )
                continue

        if low_name in MACOS_COMMON_SERVICES:
            finding_key = ("macos_service", low_name, local_port)
            if finding_key not in seen_findings:
                seen_findings.add(finding_key)
                findings.append(
                    make_finding("listening_ports", f"macOS service listening on port {local_port}: {name}", 1, item)
                )
            continue

        if local_ip in ("127.0.0.1", "::1"):
            continue

        finding_key = ("generic", low_name, local_port)
        if finding_key not in seen_findings:
            seen_findings.add(finding_key)
            findings.append(
                make_finding(
                    "listening_ports",
                    f"Review this open port: {_friendly_name(name)} is waiting for incoming connections on port {local_port}",
                    3,
                    item,
                )
            )

    for limitation in limitations:
        findings.append(
            make_finding(
                "listening_ports",
                limitation,
                1,
                {},
            )
        )

    return {
        "component": "listening_ports",
        "items": items,
        "findings": findings,
    }
