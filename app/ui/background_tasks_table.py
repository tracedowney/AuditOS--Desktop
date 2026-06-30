from __future__ import annotations

from typing import Any, Dict, List

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QHeaderView, QTableWidget, QTableWidgetItem


def _role_blurb(item: Dict[str, Any]) -> str:
    explanation = str(item.get("explanation", "")).strip()
    if explanation:
        return explanation
    return "AuditOS does not have a plain-English explanation for this process yet."


class BackgroundTasksTable(QTableWidget):
    def __init__(self):
        super().__init__(0, 4)
        self._items: List[Dict[str, Any]] = []
        self.setHorizontalHeaderLabels(["Attention", "Process", "AuditOS Reads It As", "What It Means"])
        self.verticalHeader().setVisible(False)
        self.setWordWrap(True)
        header = self.horizontalHeader()
        header.setDefaultAlignment(Qt.AlignLeft | Qt.AlignVCenter)
        header.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeToContents)
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
        exe = str(item.get("exe", "")).strip()
        cmdline_preview = str(item.get("cmdline_preview", "")).strip()

        if review_reason:
            parts.append(f"Why AuditOS called this out: {review_reason}")
        if impact_hint:
            parts.append(f"Possible impact if ended: {impact_hint}")
        if exe:
            parts.append(f"Path: {exe}")
        if cmdline_preview:
            parts.append(f"Command: {cmdline_preview}")

        return "\n\n".join(part for part in parts if part)
