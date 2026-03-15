from __future__ import annotations

from PySide6.QtWidgets import QTableWidget, QTableWidgetItem


class BehaviorTable(QTableWidget):
    def __init__(self):
        super().__init__(0, 3)
        self.setHorizontalHeaderLabels(["Type", "Primary", "Detail"])
        self.horizontalHeader().setStretchLastSection(True)

    def load_behavior(self, diff: dict):
        self.setRowCount(0)

        if not diff:
            return

        for name, port, addr in diff.get("new_connections", []):
            row = self.rowCount()
            self.insertRow(row)
            self.setItem(row, 0, QTableWidgetItem("Connection"))
            self.setItem(row, 1, QTableWidgetItem(str(name)))
            self.setItem(row, 2, QTableWidgetItem(f"{addr}:{port}"))

        for name, port in diff.get("new_listening_ports", []):
            row = self.rowCount()
            self.insertRow(row)
            self.setItem(row, 0, QTableWidgetItem("Listening Port"))
            self.setItem(row, 1, QTableWidgetItem(str(name)))
            self.setItem(row, 2, QTableWidgetItem(str(port)))

        for browser, ext_id in diff.get("new_extensions", []):
            row = self.rowCount()
            self.insertRow(row)
            self.setItem(row, 0, QTableWidgetItem("Browser Extension"))
            self.setItem(row, 1, QTableWidgetItem(str(browser)))
            self.setItem(row, 2, QTableWidgetItem(str(ext_id)))