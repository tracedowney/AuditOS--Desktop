from __future__ import annotations

import subprocess
from typing import Any, Dict, List, Tuple

import psutil

from engine.platform_utils import get_os

_NETSTAT_TAIL_COLUMNS = 8
_NETSTAT_MIN_COLUMNS = 10 + 1 + _NETSTAT_TAIL_COLUMNS


def collect_active_connection_items() -> Tuple[List[Dict[str, Any]], List[str]]:
    if get_os() == "macos":
        return _collect_macos_tcp_snapshot()["active_connections"], _collect_macos_tcp_limitations("active_connections")
    return _collect_active_connection_items_psutil()


def collect_listening_port_items() -> Tuple[List[Dict[str, Any]], List[str]]:
    if get_os() == "macos":
        return _collect_macos_tcp_snapshot()["listening_ports"], _collect_macos_tcp_limitations("listening_ports")
    return _collect_listening_port_items_psutil()


def _collect_macos_tcp_limitations(section: str) -> List[str]:
    snapshot = _collect_macos_tcp_snapshot()
    hidden = snapshot["hidden_active"] if section == "active_connections" else snapshot["hidden_listening"]
    if not hidden:
        return []

    if section == "active_connections":
        return [
            f"Limited visibility: macOS blocked process-to-connection ownership lookup for {hidden} running process(es)"
        ]

    return [
        f"Limited visibility: macOS blocked process-to-socket ownership lookup for {hidden} running process(es)"
    ]


def _collect_macos_tcp_snapshot() -> Dict[str, Any]:
    try:
        proc = subprocess.run(
            ["netstat", "-anv", "-p", "tcp"],
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError as exc:
        return {
            "active_connections": [],
            "listening_ports": [],
            "hidden_active": 0,
            "hidden_listening": 0,
            "error": str(exc),
        }

    if proc.returncode != 0:
        return {
            "active_connections": [],
            "listening_ports": [],
            "hidden_active": 0,
            "hidden_listening": 0,
            "error": proc.stderr.strip() or f"netstat exited with {proc.returncode}",
        }

    pid_cache: Dict[int, Dict[str, str]] = {}
    active_connections: List[Dict[str, Any]] = []
    listening_ports: List[Dict[str, Any]] = []
    hidden_active = 0
    hidden_listening = 0
    seen_active = set()
    seen_listening = set()

    for raw_line in proc.stdout.splitlines():
        line = raw_line.strip()
        if not line.startswith("tcp"):
            continue

        parsed = _parse_macos_netstat_line(line)
        if not parsed:
            continue

        proto, local_token, remote_token, status, process_name, pid = parsed
        local_addr, local_port = _parse_endpoint(local_token, proto)
        remote_addr, remote_port = _parse_endpoint(remote_token, proto)

        if pid is None:
            if status == "LISTEN":
                hidden_listening += 1
            elif remote_port:
                hidden_active += 1
            continue

        metadata = _lookup_process_metadata(pid, process_name, pid_cache)
        name = metadata["name"] or process_name or ""
        exe = metadata["exe"]

        if status == "LISTEN":
            key = (pid, local_addr, local_port)
            if key in seen_listening:
                continue
            seen_listening.add(key)
            listening_ports.append(
                {
                    "pid": pid,
                    "name": name,
                    "exe": exe,
                    "local_addr": local_addr,
                    "local_port": local_port,
                }
            )
            continue

        if not remote_port:
            continue

        key = (pid, local_addr, local_port, remote_addr, remote_port, status)
        if key in seen_active:
            continue
        seen_active.add(key)
        active_connections.append(
            {
                "pid": pid,
                "name": name,
                "exe": exe,
                "local_addr": local_addr,
                "local_port": local_port,
                "remote_addr": remote_addr,
                "remote_port": remote_port,
                "status": status,
            }
        )

    return {
        "active_connections": active_connections,
        "listening_ports": listening_ports,
        "hidden_active": hidden_active,
        "hidden_listening": hidden_listening,
        "error": "",
    }


def _parse_macos_netstat_line(line: str) -> Tuple[str, str, str, str, str, int | None] | None:
    parts = line.split()
    if len(parts) < _NETSTAT_MIN_COLUMNS:
        return None

    proto = parts[0]
    local_token = parts[3]
    remote_token = parts[4]
    status = parts[5]
    process_field = " ".join(parts[10:-_NETSTAT_TAIL_COLUMNS]).strip()
    if not process_field:
        return proto, local_token, remote_token, status, "", None

    if ":" not in process_field:
        return proto, local_token, remote_token, status, process_field, None

    process_name, pid_text = process_field.rsplit(":", 1)
    try:
        pid = int(pid_text)
    except ValueError:
        pid = None
    return proto, local_token, remote_token, status, process_name.strip(), pid


def _parse_endpoint(token: str, proto: str) -> Tuple[str, int]:
    value = str(token).strip()
    if value in {"*.*", "*"}:
        return ("::" if proto == "tcp6" else "0.0.0.0"), 0

    if "." not in value:
        return value, 0

    host, port_text = value.rsplit(".", 1)
    host = host[:-1] if host.endswith(".") else host
    host = host or ("::" if proto == "tcp6" else "0.0.0.0")
    if host == "*":
        host = "::" if proto == "tcp6" else "0.0.0.0"

    try:
        port = int(port_text) if port_text != "*" else 0
    except ValueError:
        port = 0

    return host, port


def _lookup_process_metadata(pid: int, fallback_name: str, cache: Dict[int, Dict[str, str]]) -> Dict[str, str]:
    cached = cache.get(pid)
    if cached is not None:
        return cached

    metadata = {"name": fallback_name, "exe": ""}
    try:
        proc = psutil.Process(pid)
        metadata["name"] = proc.name() or fallback_name
        metadata["exe"] = proc.exe() or ""
    except (psutil.NoSuchProcess, psutil.AccessDenied, PermissionError):
        pass

    cache[pid] = metadata
    return metadata


def _collect_active_connection_items_psutil() -> Tuple[List[Dict[str, Any]], List[str]]:
    items: List[Dict[str, Any]] = []
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

                items.append(
                    {
                        "pid": proc.pid,
                        "name": proc.info.get("name") or "",
                        "exe": proc.info.get("exe") or "",
                        "local_addr": getattr(conn.laddr, "ip", ""),
                        "local_port": getattr(conn.laddr, "port", 0),
                        "remote_addr": getattr(conn.raddr, "ip", ""),
                        "remote_port": getattr(conn.raddr, "port", 0),
                        "status": conn.status,
                    }
                )
    except (psutil.AccessDenied, PermissionError) as exc:
        return [], [f"Limited visibility: AuditOS could not enumerate process connections on this system ({exc})"]

    limitations: List[str] = []
    if denied:
        limitations.append(
            f"Limited visibility: AuditOS could not inspect network ownership for {denied} running process(es)"
        )
    return items, limitations


def _collect_listening_port_items_psutil() -> Tuple[List[Dict[str, Any]], List[str]]:
    items: List[Dict[str, Any]] = []
    denied = 0
    seen = set()

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

                key = (proc.pid, getattr(conn.laddr, "ip", ""), getattr(conn.laddr, "port", 0))
                if key in seen:
                    continue
                seen.add(key)
                items.append(
                    {
                        "pid": proc.pid,
                        "name": proc.info.get("name") or "",
                        "exe": proc.info.get("exe") or "",
                        "local_addr": getattr(conn.laddr, "ip", ""),
                        "local_port": getattr(conn.laddr, "port", 0),
                    }
                )
    except (psutil.AccessDenied, PermissionError) as exc:
        return [], [f"Limited visibility: AuditOS could not enumerate listening sockets on this system ({exc})"]

    limitations: List[str] = []
    if denied:
        limitations.append(
            f"Limited visibility: AuditOS could not inspect socket ownership for {denied} running process(es)"
        )
    return items, limitations
