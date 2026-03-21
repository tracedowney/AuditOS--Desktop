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
            self.setItem(0, 3, QTableWidgetItem("AuditOS compared this scan with your saved baseline or previous scan and did not find anything new to call out."))
            return
        for c in changes:
            row = self.rowCount()
            self.insertRow(row)
            severity = str(c.get("severity", "")).title()
            area_key = str(c.get("category", ""))
            area = AREA_LABELS.get(area_key, area_key.replace("_", " ").title())
            self.setItem(row, 0, QTableWidgetItem(severity))
            self.setItem(row, 1, QTableWidgetItem(area))
            self.setItem(row, 2, QTableWidgetItem(str(c.get("title", ""))))
            self.setItem(row, 3, QTableWidgetItem(str(c.get("detail", ""))))

        self.resizeRowsToContents()
