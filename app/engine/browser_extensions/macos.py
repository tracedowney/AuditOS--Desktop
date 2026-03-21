from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, List, Tuple


RISKY_PERMISSIONS = {
    "tabs": 1,
    "cookies": 3,
    "history": 2,
    "browsingData": 2,
    "clipboardRead": 4,
    "declarativeNetRequest": 1,
    "declarativeNetRequestWithHostAccess": 2,
    "webRequest": 3,
    "webRequestBlocking": 3,
    "proxy": 4,
    "management": 3,
    "debugger": 5,
    "nativeMessaging": 5,
    "privacy": 2,
    "scripting": 2,
    "activeTab": 1,
}

BROAD_HOSTS = {
    "<all_urls>": 3,
    "*://*/*": 3,
    "http://*/*": 2,
    "https://*/*": 2,
}

KNOWN_UPDATE_DOMAINS = (
    "clients2.google.com",
    "edge.microsoft.com",
    "addons.mozilla.org",
)

TRUSTED_EXTENSION_HINTS = {
    "ublock",
    "ublock origin",
    "surfshark",
    "bitwarden",
    "1password",
    "lastpass",
    "dashlane",
    "adguard",
    "privacy badger",
    "duckduckgo",
    "ghostery",
    "nordpass",
    "keeper",
}

CHROMIUM_BROWSERS = {
    "chrome": Path("~/Library/Application Support/Google/Chrome"),
    "edge": Path("~/Library/Application Support/Microsoft Edge"),
    "brave": Path("~/Library/Application Support/BraveSoftware/Brave-Browser"),
    "opera": Path("~/Library/Application Support/com.operasoftware.Opera"),
}

FIREFOX_PATH = Path("~/Library/Application Support/Firefox/Profiles")


def expand(path: str | Path) -> Path:
    return Path(path).expanduser().resolve()


def safe_read_json(path: Path) -> Dict[str, Any] | None:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def make_finding(category: str, detail: str, score: int, evidence: Dict[str, Any] | None = None) -> Dict[str, Any]:
    severity = "high" if score >= 8 else "medium" if score >= 4 else "low"
    return {
        "category": category,
        "detail": detail,
        "score": score,
        "severity": severity,
        "evidence": evidence or {},
    }


def resolve_localized_name(manifest: Dict[str, Any], ext_dir: Path) -> str:
    name = manifest.get("name", "")
    if not isinstance(name, str):
        return "<unknown>"

    m = re.fullmatch(r"__MSG_(.+)__", name)
    if not m:
        return name

    key = m.group(1)
    for messages_path in (ext_dir / "_locales").glob("*/messages.json"):
        data = safe_read_json(messages_path)
        if data and key in data and isinstance(data[key], dict):
            msg = data[key].get("message")
            if isinstance(msg, str):
                return msg
    return name


def score_manifest(manifest: Dict[str, Any], ext_name: str) -> Tuple[List[Dict[str, Any]], int]:
    findings = []
    total = 0

    permissions = manifest.get("permissions", [])
    host_permissions = manifest.get("host_permissions", [])
    optional_permissions = manifest.get("optional_permissions", [])
    all_permissions = permissions + host_permissions + optional_permissions

    low_name = ext_name.lower()
    trusted = any(h in low_name for h in TRUSTED_EXTENSION_HINTS)

    has_native_messaging = False
    has_debugger = False
    has_external_connect = "externally_connectable" in manifest
    has_non_store_update_url = False
    has_all_urls = False

    for perm in all_permissions:
        if not isinstance(perm, str):
            continue

        if perm in RISKY_PERMISSIONS:
            score = RISKY_PERMISSIONS[perm]

            if trusted and perm in {
                "declarativeNetRequest",
                "declarativeNetRequestWithHostAccess",
                "webRequest",
                "webRequestBlocking",
                "privacy",
                "tabs",
                "activeTab",
            }:
                score = max(0, score - 2)

            findings.append(make_finding("permission", f"Uses permission: {perm}", score))
            total += score

        if perm == "nativeMessaging":
            has_native_messaging = True
        elif perm == "debugger":
            has_debugger = True

    for host in permissions + host_permissions:
        if not isinstance(host, str):
            continue

        if host in BROAD_HOSTS:
            score = BROAD_HOSTS[host]
            has_all_urls = True

            if trusted:
                score = max(1, score - 2)

            findings.append(make_finding("host_access", f"Broad host access: {host}", score))
            total += score

        elif "*" in host and (host.startswith("http") or host.startswith("*://")):
            score = 2 if not trusted else 1
            findings.append(make_finding("host_access", f"Wildcard host access: {host}", score))
            total += score

    update_url = manifest.get("update_url")
    if isinstance(update_url, str) and not any(d in update_url for d in KNOWN_UPDATE_DOMAINS):
        findings.append(make_finding("update_url", f"Non-standard update URL: {update_url}", 5))
        total += 5
        has_non_store_update_url = True

    if manifest.get("manifest_version") == 2:
        findings.append(make_finding("manifest_version", "Legacy Manifest V2 extension", 1))
        total += 1

    combo_score = 0
    combo_reasons = []

    if has_native_messaging:
        combo_score += 5
        combo_reasons.append("nativeMessaging")
    if has_debugger:
        combo_score += 5
        combo_reasons.append("debugger")
    if has_non_store_update_url:
        combo_score += 4
        combo_reasons.append("non-store update URL")
    if has_external_connect and has_all_urls:
        combo_score += 3
        combo_reasons.append("external messaging + broad site access")

    if combo_score:
        findings.append(
            make_finding("risk_combo", f"Risky combination present: {', '.join(combo_reasons)}", combo_score)
        )
        total += combo_score

    if trusted and not (has_native_messaging or has_debugger or has_non_store_update_url):
        total = min(total, 6)

    return findings, total


def chromium_profiles(base: Path):
    out = []

    if not base.exists():
        return out

    if (base / "Extensions").exists():
        out.append((base.name, base))

    for child in base.iterdir():
        if child.is_dir() and (child.name == "Default" or re.fullmatch(r"Profile \d+", child.name)):
            if (child / "Extensions").exists():
                out.append((child.name, child))

    return out


def run():
    items = []
    findings = []

    for browser, base in CHROMIUM_BROWSERS.items():
        for profile_name, profile_path in chromium_profiles(expand(base)):
            ext_root = profile_path / "Extensions"

            for ext_id_dir in ext_root.iterdir() if ext_root.exists() else []:
                if not ext_id_dir.is_dir():
                    continue

                versions = sorted(
                    [p for p in ext_id_dir.iterdir() if p.is_dir()],
                    key=lambda p: p.name,
                    reverse=True,
                )

                if not versions:
                    continue

                latest = versions[0]
                manifest = safe_read_json(latest / "manifest.json")
                if not manifest:
                    continue

                ext_name = resolve_localized_name(manifest, latest)
                ext_findings, total = score_manifest(manifest, ext_name)

                item = {
                    "browser": browser,
                    "profile": profile_name,
                    "id": ext_id_dir.name,
                    "name": ext_name,
                    "version": str(manifest.get("version", "")),
                    "path": str(latest),
                    "permissions": manifest.get("permissions", []) if isinstance(manifest.get("permissions"), list) else [],
                    "host_permissions": manifest.get("host_permissions", []) if isinstance(manifest.get("host_permissions"), list) else [],
                    "score": total,
                    "findings": ext_findings,
                }

                items.append(item)

                if total >= 10:
                    findings.append(make_finding(
                        "browser_extension",
                        f"High-risk extension: {item['name']} ({browser})",
                        8,
                        {"id": item["id"], "path": item["path"]},
                    ))
                elif total >= 5:
                    findings.append(make_finding(
                        "browser_extension",
                        f"Review extension: {item['name']} ({browser})",
                        4,
                        {"id": item["id"], "path": item["path"]},
                    ))

    firefox_root = expand(FIREFOX_PATH)
    if firefox_root.exists():
        for profile in firefox_root.iterdir():
            data = safe_read_json(profile / "extensions.json") if profile.is_dir() else None
            addons = data.get("addons", []) if isinstance(data, dict) else []

            for addon in addons:
                if isinstance(addon, dict):
                    items.append({
                        "browser": "firefox",
                        "profile": profile.name,
                        "id": addon.get("id", ""),
                        "name": addon.get("defaultLocale", {}).get("name", addon.get("id", "<unknown>")),
                        "version": addon.get("version", ""),
                        "path": addon.get("path", ""),
                        "score": 0,
                        "findings": [],
                    })

    items.sort(key=lambda x: x["score"], reverse=True)
    return {"component": "browser_extensions", "items": items, "findings": findings}
