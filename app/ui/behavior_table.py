from PySide6.QtWidgets import QTableWidget, QTableWidgetItem


class BehaviorTable(QTableWidget):
    def __init__(self):
        super().__init__(0, 3)
        self.setHorizontalHeaderLabels(["Type", "Name", "Detail"])
        self.horizontalHeader().setStretchLastSection(True)

    def load_behavior(self, behavior):
        self.setRowCount(0)

        for name, port, addr in behavior.get("new_connections", []):
            row = self.rowCount()
            self.insertRow(row)
            self.setItem(row, 0, QTableWidgetItem("Connection"))
            self.setItem(row, 1, QTableWidgetItem(str(name)))
            self.setItem(row, 2, QTableWidgetItem(f"{addr}:{port}"))

        for name, port in behavior.get("new_listening_ports", []):
            row = self.rowCount()
            self.insertRow(row)
            self.setItem(row, 0, QTableWidgetItem("Listening Port"))
            self.setItem(row, 1, QTableWidgetItem(str(name)))
            self.setItem(row, 2, QTableWidgetItem(str(port)))

        for browser, ext_id in behavior.get("new_extensions", []):
            row = self.rowCount()
            self.insertRow(row)
            self.setItem(row, 0, QTableWidgetItem("Extension"))
            self.setItem(row, 1, QTableWidgetItem(str(browser)))
            self.setItem(row, 2, QTableWidgetItem(str(ext_id)))

        for server in behavior.get("new_dns_servers", []):
            row = self.rowCount()
            self.insertRow(row)
            self.setItem(row, 0, QTableWidgetItem("DNS"))
            self.setItem(row, 1, QTableWidgetItem("DNS Server"))
            self.setItem(row, 2, QTableWidgetItem(str(server)))

        for item in behavior.get("new_startup_items", []):
            row = self.rowCount()
            self.insertRow(row)
            self.setItem(row, 0, QTableWidgetItem("Startup Item"))
            self.setItem(row, 1, QTableWidgetItem(str(item)))
            self.setItem(row, 2, QTableWidgetItem("Observed since last scan"))

        for task in behavior.get("new_scheduled_tasks", []):
            row = self.rowCount()
            self.insertRow(row)
            self.setItem(row, 0, QTableWidgetItem("Scheduled Task"))
            self.setItem(row, 1, QTableWidgetItem(str(task)))
            self.setItem(row, 2, QTableWidgetItem("Observed since last scan"))

        if self.rowCount() == 0:
            self.insertRow(0)
            self.setItem(0, 0, QTableWidgetItem("Info"))
            self.setItem(0, 1, QTableWidgetItem("Behavior"))
            if behavior.get("has_previous"):
                detail = "No new behavior detected since the last comparable scan."
            else:
                detail = "No previous scan snapshot yet. Run another scan later to compare behavior."
            self.setItem(0, 2, QTableWidgetItem(detail))
