from __future__ import annotations

from typing import Any, Dict, List
import psutil


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


def audit_listening_ports() -> Dict[str, Any]:
    items: List[Dict[str, Any]] = []
    findings: List[Dict[str, Any]] = []
    denied = 0

    seen = set()
    seen_findings = set()

    try:
        for proc in psutil.process_iter(attrs=["pid", "name", "exe"]):
            try:
                conns = proc.net_connections(kind="inet")
            except (psutil.NoSuchProcess, psutil.AccessDenied, PermissionError):
                denied += 1
                continue

            for conn in conns:
                if conn.status != psutil.CONN_LISTEN:
                    continue

                pid = proc.pid
                name = proc.info.get("name") or ""
                exe = proc.info.get("exe") or ""
                local_ip = getattr(conn.laddr, "ip", "")
                local_port = getattr(conn.laddr, "port", 0)

                key = (pid, local_ip, local_port)
                if key in seen:
                    continue
                seen.add(key)

                item = {
                    "pid": pid,
                    "name": name,
                    "exe": exe,
                    "local_addr": local_ip,
                    "local_port": local_port,
                }
                items.append(item)

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
                                make_finding("listening_ports", f"Windows service listening on dynamic RPC port {local_port}: {name}", 1, item)
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
                        make_finding("listening_ports", f"Unexpected listening port {local_port}: {name}", 3, item)
                    )
    except (psutil.AccessDenied, PermissionError) as exc:
        return {
            "component": "listening_ports",
            "items": items,
            "findings": [
                make_finding(
                    "listening_ports",
                    "Limited visibility: AuditOS could not enumerate listening sockets on this system",
                    1,
                    {"error": str(exc)},
                )
            ],
        }

    if denied:
        findings.append(
            make_finding(
                "listening_ports",
                f"Limited visibility: macOS denied access to {denied} process socket list(s)",
                1,
                {"denied_processes": denied},
            )
        )

    return {
        "component": "listening_ports",
        "items": items,
        "findings": findings,
    }
