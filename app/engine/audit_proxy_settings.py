from __future__ import annotations

import argparse
import json
import re

from .common_utils import make_finding, run_command


def audit_proxy_settings():
    key = r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
    code, stdout, stderr = run_command(["reg", "query", key])

    proxy_enable = None
    proxy_server = None
    auto_config_url = None

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

    findings = []
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


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--pretty", action="store_true")
    args = ap.parse_args()
    print(json.dumps(audit_proxy_settings(), indent=2 if args.pretty else None))