from __future__ import annotations

from typing import Any, Dict, List

import psutil

from .common_utils import make_finding


SCRIPT_HOSTS = {
    "bash",
    "cmd.exe",
    "cscript.exe",
    "mshta.exe",
    "osascript",
    "powershell.exe",
    "pwsh.exe",
    "python",
    "python.exe",
    "pythonw.exe",
    "sh",
    "wscript.exe",
    "zsh",
}

WINDOWS_SYSTEM_HINTS = {
    "backgroundtaskhost.exe": {
        "friendly": "Windows background task host",
        "expected_paths": ("\\windows\\system32\\",),
        "explanation": "Runs background tasks for Windows features and some Microsoft apps.",
        "impact_hint": "Ending it may interrupt Windows notifications or app background work until it restarts.",
    },
    "lsass.exe": {
        "friendly": "Windows security service",
        "expected_paths": ("\\windows\\system32\\",),
        "explanation": "Handles Windows sign-in and local security policy work.",
        "impact_hint": "Ending it can destabilize Windows or force a shutdown or sign-out.",
    },
    "services.exe": {
        "friendly": "Windows services manager",
        "expected_paths": ("\\windows\\system32\\",),
        "explanation": "Starts and manages core Windows background services.",
        "impact_hint": "Ending it can break core services and destabilize Windows.",
    },
    "dwm.exe": {
        "friendly": "Windows desktop window manager",
        "expected_paths": ("\\windows\\system32\\",),
        "explanation": "Draws windows, transparency effects, and other desktop visuals.",
        "impact_hint": "Ending it can disrupt the Windows desktop and usually causes it to restart.",
    },
    "explorer.exe": {
        "friendly": "Windows shell",
        "expected_paths": ("\\windows\\",),
        "explanation": "Provides the taskbar, desktop, and File Explorer shell experience.",
        "impact_hint": "Ending it usually restarts the desktop shell and can temporarily close the taskbar or file browser.",
    },
    "searchhost.exe": {
        "friendly": "Windows search host",
        "expected_paths": ("\\windows\\systemapps\\", "\\windows\\system32\\"),
        "explanation": "Supports Windows search and Start menu lookup behavior.",
        "impact_hint": "Ending it usually only interrupts search features until Windows restarts it.",
    },
    "searchindexer.exe": {
        "friendly": "Windows search indexer",
        "expected_paths": ("\\windows\\system32\\",),
        "explanation": "Indexes files and content so Windows search can respond faster.",
        "impact_hint": "Ending it usually pauses indexing until Windows restarts it.",
    },
    "securityhealthservice.exe": {
        "friendly": "Windows security health service",
        "expected_paths": ("\\windows\\system32\\",),
        "explanation": "Supports Windows Security status, health checks, and notifications.",
        "impact_hint": "Ending it may interrupt security notifications until it restarts.",
    },
    "spoolsv.exe": {
        "friendly": "Windows print spooler",
        "expected_paths": ("\\windows\\system32\\",),
        "explanation": "Handles print jobs and printer coordination.",
        "impact_hint": "Ending it usually stops printing, but should not harm Windows itself.",
    },
    "svchost.exe": {
        "friendly": "Windows service host",
        "expected_paths": ("\\windows\\system32\\",),
        "explanation": "Hosts one or more Windows background services.",
        "impact_hint": "Ending it may interrupt Windows features or services that depend on it.",
    },
    "system": {
        "friendly": "Windows System",
        "expected_paths": (),
        "explanation": "Represents core Windows kernel and driver activity.",
        "impact_hint": "This is part of the operating system itself and should not be force-ended.",
    },
    "taskhostw.exe": {
        "friendly": "Windows task host",
        "expected_paths": ("\\windows\\system32\\",),
        "explanation": "Hosts certain Windows background tasks and scheduled task components.",
        "impact_hint": "Ending it may interrupt whichever Windows task it is hosting until Windows restarts it.",
    },
    "wininit.exe": {
        "friendly": "Windows startup service",
        "expected_paths": ("\\windows\\system32\\",),
        "explanation": "Starts important Windows session and service processes during boot.",
        "impact_hint": "Ending it can destabilize Windows or force a restart or sign-out.",
    },
}

MACOS_SYSTEM_HINTS = {
    "cfprefsd": {
        "friendly": "macOS preferences service",
        "expected_paths": ("/system/", "/usr/", "/sbin/", "/bin/"),
        "explanation": "Handles app and system preference reads and writes in the background.",
        "impact_hint": "Ending it usually causes it to relaunch; apps may briefly lose preference access.",
    },
    "distnoted": {
        "friendly": "macOS distributed notifications service",
        "expected_paths": ("/system/", "/usr/", "/sbin/", "/bin/"),
        "explanation": "Relays certain notifications and events between macOS processes.",
        "impact_hint": "Ending it may briefly interrupt inter-process notifications until macOS restarts it.",
    },
    "kernel_task": {
        "friendly": "macOS kernel task",
        "expected_paths": (),
        "explanation": "Represents core macOS kernel work and thermal protection behavior.",
        "impact_hint": "This is part of the operating system itself and should not be force-ended.",
    },
    "launchd": {
        "friendly": "macOS launch service",
        "expected_paths": ("/sbin/launchd",),
        "explanation": "Starts and supervises many macOS background services and app helpers.",
        "impact_hint": "Ending it is not a normal user action and may destabilize the system session.",
    },
    "loginwindow": {
        "friendly": "macOS login window",
        "expected_paths": ("/system/", "/applications/", "/system/applications/"),
        "explanation": "Manages sign-in, lock screen, and user session flow on macOS.",
        "impact_hint": "Ending it usually signs you out or restarts the desktop session.",
    },
    "locationd": {
        "friendly": "macOS location service",
        "expected_paths": ("/system/", "/usr/", "/sbin/", "/bin/"),
        "explanation": "Manages location access for apps and system features.",
        "impact_hint": "Ending it may interrupt location-aware features until macOS restarts it.",
    },
    "mds": {
        "friendly": "macOS Spotlight indexing service",
        "expected_paths": ("/system/", "/usr/", "/sbin/", "/bin/"),
        "explanation": "Indexes files so Spotlight and Finder search can work quickly.",
        "impact_hint": "Ending it usually only pauses search indexing until macOS restarts it.",
    },
    "nsurlsessiond": {
        "friendly": "macOS background download service",
        "expected_paths": ("/system/", "/usr/", "/sbin/", "/bin/"),
        "explanation": "Handles some background uploads and downloads for apps on macOS.",
        "impact_hint": "Ending it may pause background network transfers until macOS restarts it.",
    },
    "runningboardd": {
        "friendly": "macOS app lifecycle service",
        "expected_paths": ("/system/", "/usr/", "/sbin/", "/bin/"),
        "explanation": "Helps macOS manage app execution priority and background activity.",
        "impact_hint": "Ending it may affect how macOS manages app background execution until it restarts.",
    },
    "tccd": {
        "friendly": "macOS privacy permissions service",
        "expected_paths": ("/system/", "/usr/", "/sbin/", "/bin/"),
        "explanation": "Controls app permission checks for privacy-sensitive features like files, camera, and microphone.",
        "impact_hint": "Ending it may briefly interrupt permission checks until macOS restarts it.",
    },
    "trustd": {
        "friendly": "macOS trust service",
        "expected_paths": ("/system/", "/usr/", "/sbin/", "/bin/"),
        "explanation": "Verifies certificates and trust decisions for apps and websites.",
        "impact_hint": "Ending it may briefly interrupt certificate checks until it restarts.",
    },
    "windowserver": {
        "friendly": "macOS window server",
        "expected_paths": ("/system/", "/usr/", "/sbin/", "/bin/"),
        "explanation": "Draws app windows, the desktop, and visual interface elements.",
        "impact_hint": "Ending it usually signs you out or restarts the desktop session.",
    },
}

KNOWN_APP_HELPERS = {
    "adobe desktop service.exe": "Part of Adobe Creative Cloud background update and sign-in work.",
    "adobeipcbroker.exe": "Part of Adobe Creative Cloud app communication and background services.",
    "cfnetworkagent": "Handles networking tasks for apps on macOS.",
    "chrome.exe": "Part of Google Chrome or another Chrome-based app.",
    "code.exe": "Part of Visual Studio Code.",
    "discord.exe": "Part of Discord background chat, update, or voice features.",
    "dropbox.exe": "Part of Dropbox sync and notification work.",
    "firefox.exe": "Part of Mozilla Firefox.",
    "googlecrashhandler.exe": "Part of Google app crash reporting or update support.",
    "msedge.exe": "Part of Microsoft Edge.",
    "onedrive.exe": "Part of Microsoft OneDrive sync.",
    "prl_tools_service.exe": "Part of Parallels Tools integration between the VM and host.",
    "rapportd": "Supports Apple continuity and device handoff features.",
    "sharingd": "Supports Apple sharing and continuity features.",
    "slack.exe": "Part of Slack background messaging and notifications.",
    "spotify.exe": "Part of Spotify background playback or update behavior.",
    "steamwebhelper.exe": "Part of the Steam client web and storefront interface.",
    "teams.exe": "Part of Microsoft Teams.",
    "zoom.us": "Part of Zoom meetings, audio/video, or update support on macOS.",
    "zoom.exe": "Part of Zoom meetings, audio/video, or update support on Windows.",
}

GENERIC_HELPER_HINTS = ("agent", "assistant", "daemon", "helper", "host", "service", "updater")
REVIEW_WORTHY_COMMAND_TOKENS = (
    "-enc",
    "-encodedcommand",
    "-nop",
    "-windowstyle",
    "downloadstring",
    "frombase64string",
    "http://",
    "https://",
)
SAFE_APP_PATH_HINTS = (
    "\\program files\\",
    "\\windows\\",
    "/applications/",
    "/library/",
    "/system/",
    "/usr/",
    "/bin/",
    "/sbin/",
)
UNUSUAL_PATH_HINTS = (
    "\\appdata\\local\\temp\\",
    "\\downloads\\",
    "\\temp\\",
    "/desktop/",
    "/downloads/",
    "/private/tmp/",
    "/tmp/",
)


def _friendly_name(name: str) -> str:
    normalized = str(name).strip().lower()
    if normalized in WINDOWS_SYSTEM_HINTS:
        return WINDOWS_SYSTEM_HINTS[normalized]["friendly"]
    if normalized in MACOS_SYSTEM_HINTS:
        return MACOS_SYSTEM_HINTS[normalized]["friendly"]
    return name


def _path_is_unusual(path: str) -> bool:
    lowered = str(path or "").strip().lower()
    return any(hint in lowered for hint in UNUSUAL_PATH_HINTS)


def _path_is_expected(expected_paths: tuple[str, ...], path: str) -> bool:
    lowered = str(path or "").strip().lower()
    return any(fragment in lowered for fragment in expected_paths)


def _cmdline_preview(cmdline: List[str]) -> str:
    if not cmdline:
        return ""
    preview = " ".join(str(part) for part in cmdline[:6]).strip()
    return preview[:220]


def _looks_like_script_host(name: str) -> bool:
    return str(name).strip().lower() in SCRIPT_HOSTS


def _looks_like_generic_helper(name: str) -> bool:
    lowered = str(name).strip().lower()
    return any(token in lowered for token in GENERIC_HELPER_HINTS)


def _command_line_is_review_worthy(cmdline: List[str]) -> bool:
    joined = " ".join(str(part).lower() for part in cmdline)
    return any(token in joined for token in REVIEW_WORTHY_COMMAND_TOKENS)


def _app_path_hint(path: str) -> bool:
    lowered = str(path or "").strip().lower()
    return any(fragment in lowered for fragment in SAFE_APP_PATH_HINTS)


def _system_hint(name: str) -> Dict[str, Any] | None:
    lowered = str(name).strip().lower()
    return WINDOWS_SYSTEM_HINTS.get(lowered) or MACOS_SYSTEM_HINTS.get(lowered)


def _classify_process(name: str, exe: str, cmdline: List[str]) -> Dict[str, str]:
    lowered = str(name).strip().lower()
    hint = _system_hint(name)
    if hint:
        return {
            "role": "system",
            "friendly_name": hint["friendly"],
            "explanation": hint["explanation"],
            "impact_hint": hint["impact_hint"],
        }

    if _looks_like_script_host(name):
        return {
            "role": "script_host",
            "friendly_name": _friendly_name(name),
            "explanation": (
                f"{_friendly_name(name)} can run commands or scripts in the background for apps, automation, or admin tasks."
            ),
            "impact_hint": (
                "Ending it stops the current script or command session. The impact depends on what launched it."
            ),
        }

    if lowered in KNOWN_APP_HELPERS:
        return {
            "role": "app_helper",
            "friendly_name": _friendly_name(name),
            "explanation": KNOWN_APP_HELPERS[lowered],
            "impact_hint": "Ending it usually affects the related app more than the operating system.",
        }

    if _looks_like_generic_helper(name) or _app_path_hint(exe):
        return {
            "role": "app_helper",
            "friendly_name": _friendly_name(name),
            "explanation": (
                f"{_friendly_name(name)} looks like a background helper or service for another installed app."
            ),
            "impact_hint": (
                "Ending it may interrupt sync, notifications, updates, or other helper work for that app until it restarts."
            ),
        }

    return {
        "role": "unknown",
        "friendly_name": _friendly_name(name),
        "explanation": (
            f"AuditOS could not confidently classify {_friendly_name(name)} from its name and executable path alone."
        ),
        "impact_hint": "Do not end it just because the name is unfamiliar. Verify its path and what launched it first.",
    }


def _role_label(role: str) -> str:
    return {
        "app_helper": "Likely app helper",
        "script_host": "Script or command host",
        "system": "Likely operating system process",
        "unknown": "Not yet classified",
    }.get(str(role), "Background task")


def _mark_item_review(item: Dict[str, Any], status: str, label: str, reason: str):
    item["review_status"] = status
    item["review_label"] = label
    item["review_reason"] = reason


def audit_background_tasks() -> Dict[str, Any]:
    items: List[Dict[str, Any]] = []
    findings: List[Dict[str, Any]] = []
    denied = 0
    seen_findings: set[tuple[str, str]] = set()

    try:
        for proc in psutil.process_iter(attrs=["pid", "name", "exe", "cmdline", "status", "username"]):
            try:
                name = proc.info.get("name") or f"PID {proc.pid}"
                exe = proc.info.get("exe") or ""
                cmdline = proc.info.get("cmdline") or []
                if not isinstance(cmdline, list):
                    cmdline = []
                username = proc.info.get("username") or ""
                status = proc.info.get("status") or ""
            except (psutil.NoSuchProcess, psutil.AccessDenied, PermissionError):
                denied += 1
                continue

            classification = _classify_process(name, exe, cmdline)
            item = {
                "pid": proc.pid,
                "name": name,
                "friendly_name": classification["friendly_name"],
                "exe": exe,
                "cmdline": cmdline,
                "cmdline_preview": _cmdline_preview(cmdline),
                "status": status,
                "username": username,
                "role": classification["role"],
                "role_label": _role_label(classification["role"]),
                "explanation": classification["explanation"],
                "impact_hint": classification["impact_hint"],
                "review_status": "standard",
                "review_label": "Likely normal",
                "review_reason": "",
            }
            items.append(item)

            hint = _system_hint(name)
            command_is_review_worthy = _command_line_is_review_worthy(cmdline)
            unusual_path = _path_is_unusual(exe)

            if hint and exe and hint["expected_paths"] and not _path_is_expected(hint["expected_paths"], exe):
                detail = (
                    f"Review this background task: {classification['friendly_name']} looks like a core system process, but its location does not match the normal operating system path"
                )
                _mark_item_review(
                    item,
                    "review",
                    "Review first",
                    "This process name matches a core operating system task, but the file path does not look like the normal system location.",
                )
                if ("background_tasks", detail) not in seen_findings:
                    findings.append(make_finding("background_tasks", detail, 8, item))
                    seen_findings.add(("background_tasks", detail))
                continue

            if unusual_path:
                detail = f"Review this background task: {classification['friendly_name']} is running from an unusual user-controlled location"
                score = 8 if command_is_review_worthy or classification["role"] in {"script_host", "system"} else 6
                _mark_item_review(
                    item,
                    "review",
                    "Review first",
                    "This process is running from a location where user-downloaded files or temporary files often live.",
                )
                if ("background_tasks", detail) not in seen_findings:
                    findings.append(make_finding("background_tasks", detail, score, item))
                    seen_findings.add(("background_tasks", detail))
                continue

            if classification["role"] == "script_host":
                if command_is_review_worthy:
                    detail = (
                        f"Review this background task: {classification['friendly_name']} can run commands or scripts, and its command line looks unusually powerful or remote-driven"
                    )
                    score = 8
                    _mark_item_review(
                        item,
                        "review",
                        "Review first",
                        "This script or command host is running with arguments that often deserve closer review.",
                    )
                    if ("background_tasks", detail) not in seen_findings:
                        findings.append(make_finding("background_tasks", detail, score, item))
                        seen_findings.add(("background_tasks", detail))
                else:
                    _mark_item_review(
                        item,
                        "review",
                        "Worth recognizing",
                        "This background task can run commands or scripts. It may be normal, but you should recognize what launched it.",
                    )
            elif classification["role"] == "unknown":
                _mark_item_review(
                    item,
                    "unknown",
                    "Not yet classified",
                    "AuditOS could not confidently map this process to a known operating system task or a familiar app helper.",
                )

    except (psutil.AccessDenied, PermissionError) as exc:
        return {
            "component": "background_tasks",
            "items": items,
            "findings": [
                make_finding(
                    "background_tasks",
                    "Limited visibility: AuditOS could not enumerate background processes on this system",
                    1,
                    {"error": str(exc)},
                )
            ],
        }

    if denied:
        findings.append(
            make_finding(
                "background_tasks",
                f"Limited visibility: the operating system denied access to {denied} process record(s)",
                1,
                {"denied_processes": denied},
            )
        )

    status_order = {"review": 0, "unknown": 1, "standard": 2}
    items.sort(
        key=lambda item: (
            status_order.get(str(item.get("review_status", "standard")), 3),
            str(item.get("friendly_name", item.get("name", ""))).lower(),
            int(item.get("pid", 0)),
        )
    )

    return {
        "component": "background_tasks",
        "items": items,
        "findings": findings,
    }
