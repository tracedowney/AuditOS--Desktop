from __future__ import annotations

import re
from typing import Dict, List

MACOS_PRIVACY_SETTINGS_URL = "x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles"
MACOS_PRIVACY_HELP_URL = "https://support.apple.com/guide/mac-help/change-privacy-security-settings-on-mac-mchl211c911f/mac"


def _is_macos(host_os: str) -> bool:
    normalized = str(host_os).strip().lower()
    return "darwin" in normalized or "mac" in normalized


def _extract_denied_count(note: str) -> int | None:
    match = re.search(r"(\d+)", str(note))
    if not match:
        return None
    try:
        return int(match.group(1))
    except ValueError:
        return None


def describe_limitation(note: str, host_os: str = "") -> str:
    lower = str(note).strip().lower()
    count = _extract_denied_count(note)
    os_name = "macOS" if _is_macos(host_os) else "The operating system"
    count_label = f" for about {count} running process(es)" if count else ""

    if "process connection list" in lower or "process-to-connection ownership lookup" in lower:
        return (
            f"{os_name} blocked AuditOS from matching live internet connections to owning processes{count_label}. "
            "The scan still finished, but the connection picture may be incomplete. This is a visibility limit, not a list of separate problems to investigate. "
            "On macOS, this can remain true even after Full Disk Access because per-process network ownership may still require higher privileges."
        )

    if "process socket list" in lower or "process-to-socket ownership lookup" in lower:
        return (
            f"{os_name} blocked AuditOS from matching some listening sockets to owning processes{count_label}. "
            "The open-port view may be incomplete. This is a visibility limit, not a list of separate problems to investigate. "
            "On macOS, this can remain true even after Full Disk Access because per-process socket ownership may still require higher privileges."
        )

    if "process record" in lower:
        return (
            f"{os_name} blocked AuditOS from inspecting some running process records{count_label}. "
            "The background-task view may be incomplete."
        )

    if lower.startswith("limited visibility:"):
        trimmed = str(note).split(":", 1)[-1].strip()
        if trimmed:
            return f"{os_name} reduced scan visibility: {trimmed}."

    return str(note).strip()


def summarize_limitations_for_status(limitations: List[str], host_os: str = "") -> str:
    if not limitations:
        return ""

    joined = " ".join(str(note).lower() for note in limitations)
    os_name = "macOS" if _is_macos(host_os) else "The OS"

    if ("process connection list" in joined or "process-to-connection ownership lookup" in joined) and (
        "process socket list" in joined or "process-to-socket ownership lookup" in joined
    ):
        return f"{os_name} reduced some live network ownership visibility"

    if "process connection list" in joined or "process-to-connection ownership lookup" in joined:
        return f"{os_name} reduced some live connection ownership visibility"

    if "process socket list" in joined or "process-to-socket ownership lookup" in joined:
        return f"{os_name} reduced some open-port ownership visibility"

    if "process record" in joined:
        return f"{os_name} reduced some background-task visibility"

    return f"{os_name} reduced some scan visibility"


def build_visibility_guidance(limitations: List[str], host_os: str = "") -> Dict[str, object]:
    friendly_notes = [describe_limitation(note, host_os) for note in limitations if str(note).strip()]
    is_macos = _is_macos(host_os)
    joined = " ".join(str(note).lower() for note in limitations)
    has_connection_ownership_limit = "process connection list" in joined or "process-to-connection ownership lookup" in joined
    has_socket_ownership_limit = "process socket list" in joined or "process-to-socket ownership lookup" in joined
    has_process_record_limit = "process record" in joined
    actionable = is_macos and has_process_record_limit

    guidance: Dict[str, object] = {
        "actionable": actionable,
        "friendly_notes": friendly_notes,
        "status_note": summarize_limitations_for_status(limitations, host_os),
        "settings_url": None,
        "help_url": None,
        "banner_text": "",
        "instructions": [],
        "dialog_title": "Limited Audit Visibility",
        "dialog_body": (
            "AuditOS completed the scan, but parts of the system limited what could be inspected.\n\n"
            "The scan results still help, but some live details may be missing."
        ),
        "primary_button": "",
        "secondary_button": "Keep Limited Scan",
        "summary_hint": "",
    }

    if is_macos and (has_connection_ownership_limit or has_socket_ownership_limit):
        guidance.update(
            {
                "dialog_title": "macOS Limited Connection Visibility",
                "dialog_body": (
                    "macOS blocked some of AuditOS's process-to-network ownership lookups.\n\n"
                    "Full Disk Access can help some AuditOS visibility gaps, but this specific limit can remain because "
                    "AuditOS is currently using a standard app session and macOS may still require higher privileges for "
                    "per-process network ownership details."
                ),
                "banner_text": (
                    "macOS still limited some process-to-network ownership mapping. Full Disk Access may not remove this "
                    "specific limit for a standard desktop app session."
                ),
                "instructions": [
                    "Treat this as partial ownership mapping, not as hundreds of separate items to investigate.",
                    "AuditOS can still show the connections and listening ports it could attribute confidently.",
                    "To improve this further, AuditOS likely needs a different macOS collector or a privileged helper rather than another manual privacy toggle.",
                ],
                "summary_hint": (
                    "This type of macOS network ownership limit can remain even after Full Disk Access. AuditOS should describe it as partial attribution coverage, not a long review queue."
                ),
            }
        )

    if actionable:
        guidance.update(
            {
                "settings_url": MACOS_PRIVACY_SETTINGS_URL,
                "help_url": MACOS_PRIVACY_HELP_URL,
                "dialog_title": "macOS Limited Audit Visibility",
                "dialog_body": (
                    "macOS blocked AuditOS from reading some live process or network details.\n\n"
                    "AuditOS cannot override that automatically, and macOS does not always show a permission prompt for "
                    "this kind of access on its own.\n\n"
                    "AuditOS can open Privacy & Security so you can decide whether to grant broader access manually. If "
                    "you keep the current setting, AuditOS will continue scanning and clearly mark the limited areas."
                ),
                "banner_text": (
                    "macOS limited some live process and network visibility. AuditOS can open Privacy & Security and show "
                    "you how to review Full Disk Access before you rerun Deep Audit."
                ),
                "instructions": [
                    "Open System Settings to Privacy & Security.",
                    "Open Full Disk Access.",
                    "If AuditOS is already listed, turn it on. If it is not listed, click the add button and choose AuditOS.",
                    "If macOS asks you to quit and reopen AuditOS, do that.",
                    "Run Deep Audit again so AuditOS can check whether visibility improved.",
                ],
                "primary_button": "Open Privacy & Security",
                "summary_hint": (
                    "If you want fuller live process and network visibility, open Privacy & Security, review Full Disk Access for AuditOS, and rerun Deep Audit."
                ),
            }
        )

    return guidance
