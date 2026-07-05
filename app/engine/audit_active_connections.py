from __future__ import annotations

from typing import Any, Dict, List

from engine.live_network_collectors import collect_active_connection_items

COMMON_WEB_PORTS = {80, 443, 8080, 8443}
COMMON_DNS_PORTS = {53, 853}

SCRIPT_HOSTS = {
    "powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe",
    "mshta.exe", "python.exe", "pythonw.exe", "osascript", "python", "bash", "sh", "zsh"
}

KNOWN_SERVICE_APPS = {
    "apsd",
    "plex media server.exe",
    "supportassistagent.exe",
    "endpointprotection.exe",
    "surfshark.service.exe",
    "surfshark.antivirusservice.exe",
    "surfshark.exe",
    "cfnetworkagent",
    "trustd",
    "mDNSResponder",
}

LOCAL_NETWORK_PREFIXES = ("127.", "192.168.", "10.", "172.16.", "::1", "fe80:")
FRIENDLY_PROCESS_NAMES = {
    "backgroundtaskhost.exe": "Windows background task host",
    "chrome.exe": "Google Chrome",
    "code.exe": "Visual Studio Code",
    "firefox.exe": "Mozilla Firefox",
    "msedge.exe": "Microsoft Edge",
    "onedrive.exe": "Microsoft OneDrive",
    "python.exe": "Python",
    "svchost.exe": "Windows service host",
    "system": "Windows System",
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


def is_public(ip: str) -> bool:
    if not ip:
        return False
    return not ip.startswith(LOCAL_NETWORK_PREFIXES)


def _friendly_name(name: str) -> str:
    normalized = str(name).strip().lower()
    return FRIENDLY_PROCESS_NAMES.get(normalized, name)


def _target_label(ip: str, port: int) -> str:
    if not ip:
        return "an unknown address"
    if not is_public(ip):
        return f"a device or service on your local network ({ip})"
    if port in COMMON_WEB_PORTS:
        return f"a public web service ({ip})"
    if port in COMMON_DNS_PORTS:
        return f"a DNS service ({ip})"
    return f"a public internet address ({ip})"


def audit_active_connections() -> Dict[str, Any]:
    items, limitations = collect_active_connection_items()
    findings: List[Dict[str, Any]] = []
    for item in items:
        remote_ip = str(item.get("remote_addr", ""))
        remote_port = int(item.get("remote_port", 0))
        name = str(item.get("name", ""))
        exe = str(item.get("exe", ""))

        low_name = name.lower()
        agent_like = low_name in KNOWN_SERVICE_APPS or any(h in low_name for h in KNOWN_SERVICE_APPS)

        if suspicious_path(exe) and is_public(remote_ip):
            findings.append(
                make_finding(
                    "active_connections",
                    f"Review this internet connection: {_friendly_name(name)} is running from an unusual location and connected to {_target_label(remote_ip, remote_port)}",
                    8,
                    item,
                )
            )
            continue

        if low_name in SCRIPT_HOSTS and is_public(remote_ip):
            findings.append(
                make_finding(
                    "active_connections",
                    f"Review this internet connection: {_friendly_name(name)} can run commands or scripts and connected to {_target_label(remote_ip, remote_port)}",
                    6,
                    item,
                )
            )
            continue

        if agent_like:
            if is_public(remote_ip) and remote_port not in COMMON_WEB_PORTS:
                findings.append(
                    make_finding(
                        "active_connections",
                        f"Likely normal background service: {_friendly_name(name)} connected to {_target_label(remote_ip, remote_port)} using uncommon port {remote_port}",
                        1,
                        item,
                    )
                )
            continue

        if is_public(remote_ip) and remote_port not in COMMON_WEB_PORTS and remote_port not in COMMON_DNS_PORTS:
            findings.append(
                make_finding(
                    "active_connections",
                    f"Review this internet connection: {_friendly_name(name)} connected to {_target_label(remote_ip, remote_port)} on uncommon port {remote_port}",
                    3,
                    item,
                )
            )

    for limitation in limitations:
        findings.append(
            make_finding(
                "active_connections",
                limitation,
                1,
                {},
            )
        )

    return {
        "component": "active_connections",
        "items": items,
        "findings": findings,
    }
