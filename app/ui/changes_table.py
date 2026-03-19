from PySide6.QtWidgets import QTableWidget, QTableWidgetItem


class ChangesTable(QTableWidget):
    def __init__(self):
        super().__init__(0, 4)
        self.setHorizontalHeaderLabels(["Severity", "Category", "Title", "Detail"])
        self.horizontalHeader().setStretchLastSection(True)

    def load_changes(self, changes):
        self.setRowCount(0)
        if not changes:
            self.insertRow(0)
            self.setItem(0, 0, QTableWidgetItem("info"))
            self.setItem(0, 1, QTableWidgetItem("changes"))
            self.setItem(0, 2, QTableWidgetItem("No changes detected"))
            self.setItem(0, 3, QTableWidgetItem("Nothing new was detected compared with the selected comparison report."))
            return
        for c in changes:
            row = self.rowCount()
            self.insertRow(row)
            self.setItem(row, 0, QTableWidgetItem(c.get("severity", "")))
            self.setItem(row, 1, QTableWidgetItem(c.get("category", "")))
            self.setItem(row, 2, QTableWidgetItem(c.get("title", "")))
            self.setItem(row, 3, QTableWidgetItem(c.get("detail", "")))
