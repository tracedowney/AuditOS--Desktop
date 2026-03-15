from __future__ import annotations

import argparse
import json
from typing import Any, Dict

import psutil

from .common_utils import make_finding, suspicious_path

WINDOWS_CORE_PROCESSES = {
    "svchost.exe",
    "lsass.exe",
    "wininit.exe",
    "services.exe",
    "system",
    "spoolsv.exe",
}

SAFE_WINDOWS_PORTS = {
    135, 139, 445, 3389,
    5355, 5357, 5358,
    7680
}

RPC_DYNAMIC_PORT_RANGE = range(49152, 65536)


def audit_listening_ports() -> Dict[str, Any]:
    items = []
    findings = []

    for conn in psutil.net_connections(kind="inet"):

        if conn.status != psutil.CONN_LISTEN:
            continue

        pid = conn.pid or 0
        name = ""
        exe = ""

        if pid:
            try:
                proc = psutil.Process(pid)
                name = proc.name()
                exe = proc.exe()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

        local_ip = getattr(conn.laddr, "ip", "")
        local_port = getattr(conn.laddr, "port", 0)

        item = {
            "pid": pid,
            "name": name,
            "exe": exe,
            "local_addr": local_ip,
            "local_port": local_port,
        }

        items.append(item)

        low_name = name.lower()

        # suspicious execution path
        if suspicious_path(exe) and local_ip not in ("127.0.0.1", "::1", ""):
            findings.append(
                make_finding(
                    "listening_ports",
                    f"Process in user/temp path listening publicly: {name}",
                    8,
                    item,
                )
            )
            continue

        # Windows core services often listen on dynamic RPC ports
        if low_name in WINDOWS_CORE_PROCESSES:

            if local_port in SAFE_WINDOWS_PORTS:
                continue

            if local_port in RPC_DYNAMIC_PORT_RANGE:
                findings.append(
                    make_finding(
                        "listening_ports",
                        f"Windows service listening on dynamic RPC port {local_port}: {name}",
                        1,
                        item,
                    )
                )
                continue

        # Local-only listener
        if local_ip in ("127.0.0.1", "::1"):
            continue

        # generic unexpected listener
        findings.append(
            make_finding(
                "listening_ports",
                f"Unexpected listening port {local_port}: {name}",
                3,
                item,
            )
        )

    return {
        "component": "listening_ports",
        "items": items,
        "findings": findings,
    }


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--pretty", action="store_true")
    args = ap.parse_args()

    print(json.dumps(audit_listening_ports(), indent=2 if args.pretty else None))