from __future__ import annotations

import argparse
import json
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

LOCAL_NETWORK_PREFIXES = (
    "127.",
    "192.168.",
    "10.",
    "172.16.",
)


def is_public(ip: str) -> bool:
    return ip and not ip.startswith(LOCAL_NETWORK_PREFIXES)


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

            # suspicious path
            if suspicious_path(exe) and is_public(remote_ip):

                findings.append(
                    make_finding(
                        "active_connections",
                        f"Process in suspicious path has public connection: {name}",
                        8,
                        item,
                    )
                )
                continue

            # script host making public connections
            if low_name in SCRIPT_HOSTS and is_public(remote_ip):

                findings.append(
                    make_finding(
                        "active_connections",
                        f"Script host making public connection: {name}",
                        6,
                        item,
                    )
                )
                continue

            # known service applications
            if low_name in KNOWN_SERVICE_APPS:

                if is_public(remote_ip) and remote_port not in COMMON_WEB_PORTS:

                    findings.append(
                        make_finding(
                            "active_connections",
                            f"Known service using custom port {remote_port}: {name}",
                            1,
                            item,
                        )
                    )
                continue

            # generic unusual port
            if is_public(remote_ip) and remote_port not in COMMON_WEB_PORTS and remote_port not in COMMON_DNS_PORTS:

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
