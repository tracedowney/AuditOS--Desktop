from PySide6.QtWidgets import QTableWidget, QTableWidgetItem


class FindingsTable(QTableWidget):
    def __init__(self):
        super().__init__(0, 3)
        self.setHorizontalHeaderLabels(["Severity", "Category", "Detail"])
        self.horizontalHeader().setStretchLastSection(True)

    def load_findings(self, findings):
        self.setRowCount(0)
        for f in findings:
            row = self.rowCount()
            self.insertRow(row)
            self.setItem(row, 0, QTableWidgetItem(f.get("severity", "")))
            self.setItem(row, 1, QTableWidgetItem(f.get("category", "")))
            self.setItem(row, 2, QTableWidgetItem(f.get("detail", "")))
