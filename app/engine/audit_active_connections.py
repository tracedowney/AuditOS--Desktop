from __future__ import annotations

from typing import Any, Dict, List
import psutil


COMMON_WEB_PORTS = {80, 443, 8080, 8443}
COMMON_DNS_PORTS = {53, 853}

SCRIPT_HOSTS = {
    "powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe",
    "mshta.exe", "python.exe", "pythonw.exe", "osascript", "python", "bash", "sh", "zsh"
}

KNOWN_SERVICE_APPS = {
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


def audit_active_connections() -> Dict[str, Any]:
    items: List[Dict[str, Any]] = []
    findings: List[Dict[str, Any]] = []
    denied = 0

    try:
        for proc in psutil.process_iter(attrs=["pid", "name", "exe"]):
            try:
                conns = proc.net_connections(kind="inet")
            except (psutil.NoSuchProcess, psutil.AccessDenied, PermissionError):
                denied += 1
                continue

            for conn in conns:
                if not conn.raddr:
                    continue

                remote_ip = getattr(conn.raddr, "ip", "")
                remote_port = getattr(conn.raddr, "port", 0)

                name = proc.info.get("name") or ""
                exe = proc.info.get("exe") or ""

                item = {
                    "pid": proc.pid,
                    "name": name,
                    "exe": exe,
                    "local_addr": getattr(conn.laddr, "ip", ""),
                    "local_port": getattr(conn.laddr, "port", 0),
                    "remote_addr": remote_ip,
                    "remote_port": remote_port,
                    "status": conn.status,
                }
                items.append(item)

                low_name = name.lower()
                agent_like = low_name in KNOWN_SERVICE_APPS or any(h in low_name for h in KNOWN_SERVICE_APPS)

                if suspicious_path(exe) and is_public(remote_ip):
                    findings.append(
                        make_finding("active_connections", f"Process in suspicious path has public connection: {name}", 8, item)
                    )
                    continue

                if low_name in SCRIPT_HOSTS and is_public(remote_ip):
                    findings.append(
                        make_finding("active_connections", f"Script/interpreter making public connection: {name}", 6, item)
                    )
                    continue

                if agent_like:
                    if is_public(remote_ip) and remote_port not in COMMON_WEB_PORTS:
                        findings.append(
                            make_finding("active_connections", f"Known service using custom port {remote_port}: {name}", 1, item)
                        )
                    continue

                if is_public(remote_ip) and remote_port not in COMMON_WEB_PORTS and remote_port not in COMMON_DNS_PORTS:
                    findings.append(
                        make_finding("active_connections", f"Public connection on unusual port {remote_port}: {name}", 3, item)
                    )
    except (psutil.AccessDenied, PermissionError) as exc:
        return {
            "component": "active_connections",
            "items": items,
            "findings": [
                make_finding(
                    "active_connections",
                    "Limited visibility: AuditOS could not enumerate process connections on this system",
                    1,
                    {"error": str(exc)},
                )
            ],
        }

    if denied:
        findings.append(
            make_finding(
                "active_connections",
                f"Limited visibility: macOS denied access to {denied} process connection list(s)",
                1,
                {"denied_processes": denied},
            )
        )

    return {
        "component": "active_connections",
        "items": items,
        "findings": findings,
    }
