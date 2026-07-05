from __future__ import annotations

import re

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QAbstractItemView, QHeaderView, QTableWidget, QTableWidgetItem


def _friendly_item_name(name: str) -> str:
    known = {
        "backgroundtaskhost.exe": "Windows background task host",
        "chrome.exe": "Google Chrome",
        "code.exe": "Visual Studio Code",
        "firefox.exe": "Mozilla Firefox",
        "lsass.exe": "Windows security service",
        "microsoft edge": "Microsoft Edge",
        "msedge.exe": "Microsoft Edge",
        "onedrive.exe": "Microsoft OneDrive",
        "prl_tools_service.exe": "Parallels Tools service",
        "services.exe": "Windows services manager",
        "spoolsv.exe": "Windows print spooler",
        "svchost.exe": "Windows service host",
        "system": "Windows System",
        "teams.exe": "Microsoft Teams",
        "wininit.exe": "Windows startup service",
    }
    key = str(name).strip().lower()
    return known.get(key, str(name))


def _normalize_task_label(task: str) -> str:
    normalized = str(task).strip()
    if normalized.startswith("com.apple.mdworker.shared."):
        return "com.apple.mdworker.shared"

    parts = normalized.split(".")
    while parts and parts[-1].isdigit():
        parts.pop()
    return ".".join(parts) if parts else normalized


def _label_tail(label: str) -> str:
    return str(label).rsplit(".", 1)[-1]


def _pretty_words(value: str) -> str:
    text = str(value).replace("_", " ")
    text = re.sub(r"(?<!^)(?=[A-Z])", " ", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text.title() if text else str(value)


def _application_label_name(task: str) -> str:
    normalized = _normalize_task_label(task)
    if normalized.startswith("application."):
        bundle_id = normalized[len("application."):]
        if bundle_id == "com.apple.Passwords":
            return "Apple Passwords app helper"
        if bundle_id == "com.auditos.desktop":
            return "AuditOS app helper"
        if bundle_id.startswith("com.apple."):
            return f"{_pretty_words(_label_tail(bundle_id))} app helper"
        return f"{_pretty_words(_label_tail(bundle_id))} app helper"
    return normalized


def _friendly_task_name(task: str) -> str:
    normalized = _normalize_task_label(task)
    known = {
        "com.apple.mdworker.shared": "macOS Spotlight metadata worker",
        "com.apple.package-script-service": "macOS installer script service",
        "com.anthropic.claudefordesktop.ShipIt": "Claude Desktop updater",
        "com.setapp.DesktopClient.SetappAgent": "Setapp background agent",
        "com.setapp.DesktopClient.SetappAssistant": "Setapp helper service",
    }
    if normalized in known:
        return known[normalized]
    if normalized.startswith("application."):
        return _application_label_name(normalized)
    if normalized.startswith("com.apple."):
        return f"macOS system launch job ({_pretty_words(_label_tail(normalized))})"
    if normalized.startswith("com.anthropic."):
        return f"Claude-related launch job ({_pretty_words(_label_tail(normalized))})"
    return normalized


def _normality_label(name: str) -> str:
    standard = {
        "backgroundtaskhost.exe",
        "lsass.exe",
        "prl_tools_service.exe",
        "services.exe",
        "spoolsv.exe",
        "svchost.exe",
        "system",
        "wininit.exe",
    }
    key = str(name).strip().lower()
    return "Likely standard background activity" if key in standard else "Worth recognizing and confirming"


def _connection_target(addr: str, port: int) -> str:
    if not addr:
        return "an unknown destination"
    if addr.startswith(("127.", "192.168.", "10.", "172.16.", "::1", "fe80:")):
        return f"a device or service on your local network ({addr})"
    if int(port) in {80, 443, 8080, 8443}:
        return f"a web service on the internet ({addr})"
    if int(port) in {53, 853}:
        return f"a DNS service ({addr})"
    return f"a public internet address ({addr})"


def _connection_summary(name: str, port: int, addr: str, *, is_new: bool) -> str:
    friendly = _friendly_item_name(name)
    timing = "started talking to" if is_new else "is currently talking to"
    return f"{friendly} {timing} {_connection_target(addr, port)}."


def _connection_detail(name: str, port: int, addr: str, *, is_new: bool) -> str:
    friendly = _friendly_item_name(name)
    normality = _normality_label(name)
    timing = "since the last scan" if is_new else "right now"
    return (
        f"{normality}. {friendly} connected to {_connection_target(addr, port)} on port {port} {timing}.\n\n"
        "Internet activity can be completely normal for browsers, sync tools, update agents, messaging apps, and background services. "
        "This row is most useful when you do not recognize the program or the destination pattern."
    )


def _listening_summary(name: str, port: int, *, is_new: bool) -> str:
    friendly = _friendly_item_name(name)
    timing = "started waiting for" if is_new else "is waiting for"
    return f"{friendly} {timing} incoming connections on port {port}."


def _listening_meaning(name: str, port: int, *, is_new: bool) -> str:
    standard_ports = {
        135: "Windows service coordination",
        139: "Windows file or printer sharing",
        445: "Windows file or printer sharing",
        5040: "Windows background service communication",
    }
    normality = _normality_label(name)
    timing = "since the last scan" if is_new else "right now"
    if int(port) in standard_ports:
        return (
            f"{normality}. Listening means this program is waiting for another app or device to contact it, usually for "
            f"{standard_ports[int(port)]}. AuditOS saw that on port {port} {timing}."
        )
    if 49152 <= int(port) <= 65535:
        return (
            f"{normality}. Listening means this program is waiting for another app or service to contact it on an internal "
            f"communication port. AuditOS saw port {port} {timing}."
        )
    return (
        f"{normality}. Listening means this program is waiting for another app or device to contact it on port {port}. "
        f"AuditOS saw that {timing}."
    )


def _extension_summary(browser: str) -> str:
    return f"A browser extension appeared in {browser} that was not part of the earlier snapshot."


def _extension_detail(browser: str, ext_id: str) -> str:
    return (
        f"AuditOS saw a browser extension in {browser} that was not present in the earlier comparison snapshot.\n\n"
        "New extensions can be harmless, but they can also add page access, account integration, or scripting ability depending on their permissions.\n\n"
        f"Extension ID: {ext_id}"
    )


def _dns_summary(server: str) -> str:
    return f"This system started using DNS server {server} for some name lookups."


def _dns_detail(server: str) -> str:
    return (
        f"DNS server {server} was not part of the earlier comparison snapshot.\n\n"
        "DNS servers translate website names into network addresses. A change here can affect privacy, filtering, reliability, or which network provider answers your lookups."
    )


def _startup_summary(item: str) -> str:
    return f"{item} can launch automatically when you sign in or when the system starts."


def _startup_detail(item: str) -> str:
    return (
        f"{item} was not part of the earlier comparison snapshot.\n\n"
        "Startup items help apps stay persistent by launching automatically. They are worth recognizing because they can keep running even when you did not open them manually."
    )


def _task_summary(task: str) -> str:
    normalized = _normalize_task_label(task)
    friendly = _friendly_task_name(task)
    if normalized == "com.apple.mdworker.shared":
        return "macOS created another Spotlight metadata worker, which is usually tied to indexing or search work."
    if normalized.startswith("application."):
        return f"{friendly} appeared as a launchd helper entry for an app session, not as a standalone mystery task."
    if normalized.startswith("com.apple."):
        return f"{friendly} is a macOS launchd job. These are often normal system helpers rather than user-created scheduled tasks."
    if "shipit" in normalized.lower() or "updater" in normalized.lower():
        return f"{friendly} looks like an app updater or helper service that can launch in the background."
    return f"{friendly} can run on a timer or trigger without you opening it manually."


def _task_detail(task: str) -> str:
    normalized = _normalize_task_label(task)
    friendly = _friendly_task_name(task)
    if normalized == "com.apple.mdworker.shared":
        return (
            f"{friendly} was not part of the earlier comparison snapshot.\n\n"
            "On macOS this usually belongs to Spotlight metadata indexing, file previews, or search-related background work. "
            "It is more like temporary system churn than a manually scheduled task.\n\n"
            f"Raw launchd label family: {normalized}"
        )
    if normalized.startswith("application."):
        return (
            f"{friendly} was not part of the earlier comparison snapshot.\n\n"
            "On macOS, labels that start with `application.` are often per-app launchd helpers created while an app is installed, open, or doing background work. "
            "That is usually much less suspicious than the phrase \"new scheduled task\" makes it sound.\n\n"
            f"Raw launchd label: {task}"
        )
    if normalized.startswith("com.apple."):
        return (
            f"{friendly} was not part of the earlier comparison snapshot.\n\n"
            "This looks like a macOS system launchd job. Those jobs often appear and disappear as the system handles indexing, sync, notifications, media, or app support work.\n\n"
            f"Raw launchd label: {task}"
        )
    return (
        f"{friendly} was not part of the earlier comparison snapshot.\n\n"
        "Scheduled tasks are often legitimate system or app maintenance jobs, but they are also a common way to keep something running persistently in the background.\n\n"
        f"Raw task label: {task}"
    )


class BehaviorTable(QTableWidget):
    def __init__(self):
        super().__init__(0, 3)
        self.setHorizontalHeaderLabels(["What AuditOS Saw", "Program or Item", "What It Probably Means"])
        self.verticalHeader().setVisible(False)
        self.setWordWrap(True)
        self.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.setAlternatingRowColors(True)
        header = self.horizontalHeader()
        header.setDefaultAlignment(Qt.AlignLeft | Qt.AlignVCenter)
        header.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.Stretch)
        header.setSectionResizeMode(2, QHeaderView.Stretch)

    def _set_row(self, label: str, item_name: str, summary: str, detail: str):
        row = self.rowCount()
        self.insertRow(row)

        label_item = QTableWidgetItem(label)
        name_item = QTableWidgetItem(item_name)
        summary_item = QTableWidgetItem(summary)

        for cell in (label_item, name_item, summary_item):
            cell.setToolTip(detail)

        self.setItem(row, 0, label_item)
        self.setItem(row, 1, name_item)
        self.setItem(row, 2, summary_item)

    def load_behavior(self, behavior):
        self.setRowCount(0)

        new_connections = behavior.get("new_connections", [])
        current_connections = behavior.get("current_connections", [])
        new_listening = behavior.get("new_listening_ports", [])
        current_listening = behavior.get("current_listening_ports", [])

        connections = new_connections or current_connections
        listening_ports = new_listening or current_listening
        show_new_connections = bool(new_connections)
        show_new_listening = bool(new_listening)

        for name, port, addr in connections:
            friendly = _friendly_item_name(str(name))
            detail = _connection_detail(str(name), int(port), str(addr), is_new=show_new_connections)
            self._set_row(
                "New Internet Activity" if show_new_connections else "Current Internet Activity",
                friendly,
                _connection_summary(str(name), int(port), str(addr), is_new=show_new_connections),
                detail,
            )

        for name, port in listening_ports:
            friendly = _friendly_item_name(str(name))
            detail = _listening_meaning(str(name), int(port), is_new=show_new_listening)
            self._set_row(
                "New Open Port" if show_new_listening else "Current Open Port",
                friendly,
                _listening_summary(str(name), int(port), is_new=show_new_listening),
                detail,
            )

        for browser, ext_id in behavior.get("new_extensions", []):
            detail = _extension_detail(str(browser), str(ext_id))
            self._set_row(
                "New Extension",
                str(browser),
                _extension_summary(str(browser)),
                detail,
            )

        for server in behavior.get("new_dns_servers", []):
            detail = _dns_detail(str(server))
            self._set_row(
                "DNS Changed",
                str(server),
                _dns_summary(str(server)),
                detail,
            )

        for item in behavior.get("new_startup_items", []):
            detail = _startup_detail(str(item))
            self._set_row(
                "Startup Changed",
                str(item),
                _startup_summary(str(item)),
                detail,
            )

        for task in behavior.get("new_scheduled_tasks", []):
            detail = _task_detail(str(task))
            self._set_row(
                "Task Changed",
                _friendly_task_name(str(task)),
                _task_summary(str(task)),
                detail,
            )

        if self.rowCount() == 0:
            if behavior.get("has_previous"):
                detail = (
                    "AuditOS did not see any new network, startup, task, DNS, or extension behavior that stood out compared "
                    "with the previous scan."
                )
            else:
                detail = (
                    "No previous scan snapshot exists yet. Run another scan later and AuditOS will explain what changed in live "
                    "behavior over time."
                )

            self._set_row("Info", "Behavior", detail, detail)

        self.resizeRowsToContents()
