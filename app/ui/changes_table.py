from __future__ import annotations

import re

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QHeaderView, QTableWidget, QTableWidgetItem


AREA_LABELS = {
    "dns": "DNS Settings",
    "extension": "Browser Extensions",
    "listening_port": "Open Ports",
    "proxy": "Proxy Settings",
    "scheduled_task": "Automatic Tasks",
    "startup_item": "Startup Items",
}


def _friendly_program_name(name: str) -> str:
    known = {
        "chrome.exe": "Google Chrome",
        "firefox.exe": "Mozilla Firefox",
        "msedge.exe": "Microsoft Edge",
        "onedrive.exe": "Microsoft OneDrive",
        "python.exe": "Python",
        "svchost.exe": "Windows service host",
        "system": "Windows System",
    }
    key = str(name).strip().lower()
    return known.get(key, str(name))


def _extract_value(detail: str) -> str:
    parts = str(detail).split(": ", 1)
    return parts[1].strip() if len(parts) == 2 else str(detail).strip()


def _friendly_change_title(change: dict) -> str:
    category = str(change.get("category", "")).strip().lower()
    detail = str(change.get("detail", ""))
    value = _extract_value(detail)

    if category == "dns":
        return "DNS server added"

    if category == "startup_item":
        return "Startup item added"

    if category == "scheduled_task":
        return "Scheduled task added"

    if category == "proxy":
        return "Proxy setting changed"

    if category == "extension":
        return "Browser extension added"

    if category == "listening_port":
        match = re.match(r"(.+?) on port (\d+)$", value)
        if match:
            return f"{_friendly_program_name(match.group(1))} opened port {match.group(2)}"
        return "Listening port added"

    return str(change.get("title", "")).strip() or "Change detected"


def _meaning_for_change(change: dict) -> str:
    category = str(change.get("category", "")).strip().lower()
    detail = str(change.get("detail", ""))
    value = _extract_value(detail)

    if category == "dns":
        return (
            f"Your system started using DNS server {value} for some name lookups. DNS changes can affect privacy, filtering, "
            "or which network provider resolves website names."
        )

    if category == "startup_item":
        return (
            f"{value} can launch automatically when you sign in or when the system starts. New startup entries are worth "
            "recognizing because they can stay persistent in the background."
        )

    if category == "scheduled_task":
        return (
            f"{value} can run on a timer or trigger without you opening it manually. Scheduled tasks are often legitimate, "
            "but they are also a common persistence path for background activity."
        )

    if category == "proxy":
        return (
            f"{value} was not part of the earlier scan. Proxy settings can redirect, filter, or inspect network traffic "
            "before it reaches the internet."
        )

    if category == "extension":
        match = re.search(r"browser=(.*?) profile=(.*?) id=(.*)$", value)
        if match:
            browser = match.group(1).strip()
            ext_id = match.group(3).strip()
            return (
                f"A browser extension appeared in {browser} that was not in the earlier scan. New extensions can read page "
                f"content or modify browsing sessions depending on their permissions. Extension ID: {ext_id}"
            )
        return "A browser extension appeared that was not present in the earlier scan."

    if category == "listening_port":
        match = re.match(r"(.+?) on port (\d+)$", value)
        if match:
            program = _friendly_program_name(match.group(1))
            port = match.group(2)
            return (
                f"{program} was not previously seen waiting for incoming connections on port {port}. A listening port means "
                "the app can accept a connection from this machine or, in some cases, another device."
            )
        return "A new open port appeared compared with the earlier scan."

    return detail or "AuditOS saw a difference compared with the earlier scan."


class ChangesTable(QTableWidget):
    def __init__(self):
        super().__init__(0, 4)
        self.setHorizontalHeaderLabels(["Priority", "Area", "Change", "What It Means"])
        self.verticalHeader().setVisible(False)
        self.setWordWrap(True)
        header = self.horizontalHeader()
        header.setDefaultAlignment(Qt.AlignLeft | Qt.AlignVCenter)
        header.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.Stretch)

    def load_changes(self, changes):
        self.setRowCount(0)
        if not changes:
            self.insertRow(0)
            self.setItem(0, 0, QTableWidgetItem("Info"))
            self.setItem(0, 1, QTableWidgetItem("Comparison"))
            self.setItem(0, 2, QTableWidgetItem("No new changes detected"))
            self.setItem(
                0,
                3,
                QTableWidgetItem(
                    "AuditOS compared this scan with your saved baseline or previous scan and did not find anything newly different to explain."
                ),
            )
            return

        for change in changes:
            row = self.rowCount()
            self.insertRow(row)
            severity = str(change.get("severity", "")).title()
            area_key = str(change.get("category", ""))
            area = AREA_LABELS.get(area_key, area_key.replace("_", " ").title())
            self.setItem(row, 0, QTableWidgetItem(severity))
            self.setItem(row, 1, QTableWidgetItem(area))
            self.setItem(row, 2, QTableWidgetItem(_friendly_change_title(change)))
            self.setItem(row, 3, QTableWidgetItem(_meaning_for_change(change)))

        self.resizeRowsToContents()
