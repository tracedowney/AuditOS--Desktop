from __future__ import annotations

import argparse
import json
from ipaddress import ip_address
from typing import Any, Dict

import psutil

from .common_utils import COMMON_DNS_PORTS, COMMON_WEB_PORTS, make_finding, suspicious_path

SCRIPT_HOSTS = {
    "powershell.exe",
    "pwsh.exe",
    "cmd.exe",
    "wscript.exe",
    "cscript.exe",
    "mshta.exe",
    "python.exe",
    "pythonw.exe",
}

KNOWN_SERVICE_APPS = {
    "plex media server.exe",
    "supportassistagent.exe",
    "endpointprotection.exe",
}

IGNORED_STATUSES = {
    "TIME_WAIT",
}

LOCAL_NAMES = {
    "system idle process",
    "system",
}


def is_public(ip: str) -> bool:
    try:
        addr = ip_address(ip)
    except ValueError:
        return False

    return not (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_reserved
        or addr.is_unspecified
    )


def audit_active_connections() -> Dict[str, Any]:
    items = []
    findings = []

    for proc in psutil.process_iter(attrs=["pid", "name", "exe"]):
        try:
            conns = proc.net_connections(kind="inet")
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

        for conn in conns:
            if not conn.raddr:
                continue

            remote_ip = getattr(conn.raddr, "ip", "")
            remote_port = getattr(conn.raddr, "port", 0)
            local_ip = getattr(conn.laddr, "ip", "")
            local_port = getattr(conn.laddr, "port", 0)

            status = conn.status or ""
            name = proc.info.get("name") or ""
            exe = proc.info.get("exe") or ""
            low_name = name.lower()

            if status in IGNORED_STATUSES:
                continue

            if not is_public(remote_ip):
                continue

            if low_name in LOCAL_NAMES:
                continue

            item = {
                "pid": proc.pid,
                "name": name,
                "exe": exe,
                "local_addr": local_ip,
                "local_port": local_port,
                "remote_addr": remote_ip,
                "remote_port": remote_port,
                "status": status,
            }

            items.append(item)

            if suspicious_path(exe):
                findings.append(
                    make_finding(
                        "active_connections",
                        f"Process in suspicious path has public connection: {name}",
                        8,
                        item,
                    )
                )
                continue

            if low_name in SCRIPT_HOSTS:
                findings.append(
                    make_finding(
                        "active_connections",
                        f"Script host making public connection: {name}",
                        6,
                        item,
                    )
                )
                continue

            if low_name in KNOWN_SERVICE_APPS:
                if remote_port not in COMMON_WEB_PORTS:
                    findings.append(
                        make_finding(
                            "active_connections",
                            f"Known service using custom port {remote_port}: {name}",
                            1,
                            item,
                        )
                    )
                continue

            if remote_port not in COMMON_WEB_PORTS and remote_port not in COMMON_DNS_PORTS:
                findings.append(
                    make_finding(
                        "active_connections",
                        f"Public connection on unusual port {remote_port}: {name}",
                        3,
                        item,
                    )
                )

    return {
        "component": "active_connections",
        "items": items,
        "findings": findings,
    }


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--pretty", action="store_true")
    args = ap.parse_args()
    print(json.dumps(audit_active_connections(), indent=2 if args.pretty else None))