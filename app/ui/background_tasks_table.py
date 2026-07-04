from __future__ import annotations

from typing import Any, Dict, List

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QAbstractItemView, QHeaderView, QTableWidget, QTableWidgetItem


def _role_blurb(item: Dict[str, Any]) -> str:
    parts = []
    explanation = str(item.get("explanation", "")).strip()
    command_summary = str(item.get("command_summary", "")).strip()
    launch_summary = str(item.get("launch_summary", "")).strip()
    if explanation:
        parts.append(explanation)
    if command_summary:
        parts.append(command_summary)
    if launch_summary and launch_summary not in parts:
        parts.append(launch_summary)
    if parts:
        return " ".join(parts)
    return "AuditOS does not have a plain-English explanation for this process yet."


class BackgroundTasksTable(QTableWidget):
    def __init__(self):
        super().__init__(0, 4)
        self._items: List[Dict[str, Any]] = []
        self.setHorizontalHeaderLabels(["Attention", "Process", "AuditOS Reads It As", "What It Means"])
        self.verticalHeader().setVisible(False)
        self.setWordWrap(True)
        self.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.setAlternatingRowColors(True)
        header = self.horizontalHeader()
        header.setDefaultAlignment(Qt.AlignLeft | Qt.AlignVCenter)
        header.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.Stretch)
        header.setSectionResizeMode(2, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.Stretch)

    def load_tasks(self, items: List[Dict[str, Any]], empty_message: str):
        self._items = list(items)
        self.setRowCount(0)

        if not self._items:
            self.insertRow(0)
            self.setItem(0, 0, QTableWidgetItem("Info"))
            self.setItem(0, 1, QTableWidgetItem("Background Tasks"))
            self.setItem(0, 2, QTableWidgetItem("No live task list loaded"))
            self.setItem(0, 3, QTableWidgetItem(empty_message))
            return

        for item in self._items:
            row = self.rowCount()
            self.insertRow(row)

            attention = str(item.get("review_label", "Likely normal"))
            process_name = str(item.get("friendly_name") or item.get("name") or f"PID {item.get('pid', '?')}")
            role_label = str(item.get("role_label") or item.get("role", "Background task")).strip()
            meaning = _role_blurb(item)
            tooltip = self._tooltip_for_item(item)

            attention_item = QTableWidgetItem(attention)
            process_item = QTableWidgetItem(process_name)
            role_item = QTableWidgetItem(role_label)
            meaning_item = QTableWidgetItem(meaning)

            for cell in (attention_item, process_item, role_item, meaning_item):
                cell.setToolTip(tooltip)

            self.setItem(row, 0, attention_item)
            self.setItem(row, 1, process_item)
            self.setItem(row, 2, role_item)
            self.setItem(row, 3, meaning_item)

        self.resizeRowsToContents()

    def task_at_row(self, row: int) -> Dict[str, Any] | None:
        if row < 0 or row >= len(self._items):
            return None
        return self._items[row]

    def _tooltip_for_item(self, item: Dict[str, Any]) -> str:
        parts = [
            str(item.get("friendly_name") or item.get("name") or "Background task"),
            str(item.get("explanation", "")).strip(),
        ]
        review_reason = str(item.get("review_reason", "")).strip()
        impact_hint = str(item.get("impact_hint", "")).strip()
        command_summary = str(item.get("command_summary", "")).strip()
        launch_summary = str(item.get("launch_summary", "")).strip()
        parent_name = str(item.get("parent_friendly_name") or item.get("parent_name") or "").strip()
        parent_pid = item.get("ppid")
        parent_exe = str(item.get("parent_exe", "")).strip()
        parent_cmdline_preview = str(item.get("parent_cmdline_preview", "")).strip()
        exe = str(item.get("exe", "")).strip()
        cmdline_preview = str(item.get("cmdline_preview", "")).strip()

        if command_summary:
            parts.append(f"What the command suggests: {command_summary}")
        if launch_summary:
            parts.append(f"Launch context: {launch_summary}")
        if review_reason:
            parts.append(f"Why AuditOS called this out: {review_reason}")
        if impact_hint:
            parts.append(f"Possible impact if ended: {impact_hint}")
        if parent_name:
            parent_line = f"Likely parent: {parent_name}"
            if isinstance(parent_pid, int):
                parent_line += f" (PID {parent_pid})"
            parts.append(parent_line)
        if parent_exe:
            parts.append(f"Parent path: {parent_exe}")
        if parent_cmdline_preview:
            parts.append(f"Parent command: {parent_cmdline_preview}")
        if exe:
            parts.append(f"Path: {exe}")
        if cmdline_preview:
            parts.append(f"Command: {cmdline_preview}")

        return "\n\n".join(part for part in parts if part)
