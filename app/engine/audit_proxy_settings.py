from __future__ import annotations

import platform
import re
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


def _run_command(args: List[str]):
    try:
        p = subprocess.run(args, capture_output=True, text=True, encoding="utf-8", errors="ignore")
        return p.returncode, p.stdout, p.stderr
    except Exception as exc:
        return 1, "", str(exc)


def _audit_windows():
    code, stdout, stderr = _run_command(
        ["reg", "query", r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Internet Settings"]
    )

    proxy_enable = None
    proxy_server = None
    auto_config_url = None
    findings = []

    for line in stdout.splitlines():
        parts = re.split(r"\s{2,}", line.strip())
        if len(parts) < 3:
            continue
        name, value = parts[0], parts[-1]
        if name.endswith("ProxyEnable"):
            proxy_enable = value
        elif name.endswith("ProxyServer"):
            proxy_server = value
        elif name.endswith("AutoConfigURL"):
            auto_config_url = value

    if proxy_enable not in (None, "0x0", "0"):
        findings.append(make_finding("proxy", "Manual proxy enabled", 8, {"proxy_server": proxy_server}))
    if proxy_server:
        findings.append(make_finding("proxy", f"Proxy server configured: {proxy_server}", 6))
    if auto_config_url:
        findings.append(make_finding("proxy", f"AutoConfigURL / PAC in use: {auto_config_url}", 7))
    if code != 0:
        findings.append(make_finding("proxy", "Failed to read proxy registry settings", 3, {"error": stderr}))

    return {
        "component": "proxy_settings",
        "proxy_enable": proxy_enable,
        "proxy_server": proxy_server,
        "auto_config_url": auto_config_url,
        "findings": findings,
        "raw": stdout.strip(),
        "error": stderr.strip(),
    }


def _audit_macos():
    code, stdout, stderr = _run_command(["scutil", "--proxy"])
    findings = []

    proxy_enable = False
    proxy_server = ""
    auto_config_url = ""

    state: Dict[str, str] = {}
    for line in stdout.splitlines():
        if ":" not in line:
            continue
        k, v = line.split(":", 1)
        state[k.strip()] = v.strip()

    if state.get("HTTPEnable") == "1":
        proxy_enable = True
        proxy_server = f"{state.get('HTTPProxy', '')}:{state.get('HTTPPort', '')}".strip(":")
        findings.append(make_finding("proxy", f"HTTP proxy enabled: {proxy_server}", 5))

    if state.get("HTTPSEnable") == "1":
        proxy_enable = True
        https_proxy = f"{state.get('HTTPSProxy', '')}:{state.get('HTTPSPort', '')}".strip(":")
        findings.append(make_finding("proxy", f"HTTPS proxy enabled: {https_proxy}", 5))

    if state.get("ProxyAutoConfigEnable") == "1":
        auto_config_url = state.get("ProxyAutoConfigURLString", "")
        findings.append(make_finding("proxy", f"PAC / Auto Proxy Config enabled: {auto_config_url}", 6))

    if state.get("SOCKSEnable") == "1":
        proxy_enable = True
        socks_proxy = f"{state.get('SOCKSProxy', '')}:{state.get('SOCKSPort', '')}".strip(":")
        findings.append(make_finding("proxy", f"SOCKS proxy enabled: {socks_proxy}", 5))

    if code != 0:
        findings.append(make_finding("proxy", "Failed to read macOS proxy settings", 3, {"error": stderr}))

    return {
        "component": "proxy_settings",
        "proxy_enable": proxy_enable,
        "proxy_server": proxy_server,
        "auto_config_url": auto_config_url,
        "findings": findings,
        "raw": stdout.strip(),
        "error": stderr.strip(),
    }


def _audit_linux():
    return {
        "component": "proxy_settings",
        "proxy_enable": False,
        "proxy_server": "",
        "auto_config_url": "",
        "findings": [],
        "raw": "",
        "error": "",
    }


def audit_proxy_settings():
    os_name = platform.system()
    if os_name == "Windows":
        return _audit_windows()
    if os_name == "Darwin":
        return _audit_macos()
    return _audit_linux()
