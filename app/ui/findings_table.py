from PySide6.QtWidgets import QTableWidget, QTableWidgetItem


AREA_LABELS = {
    "active_connections": "Internet Connections",
    "browser_extension": "Browser Extensions",
    "browser_extensions": "Browser Extensions",
    "certificates": "Certificates",
    "dns_settings": "DNS Settings",
    "listening_ports": "Open Ports",
    "network_interfaces": "Network Adapters",
    "proxy": "Proxy Settings",
    "routes": "Network Routes",
    "scheduled_tasks": "Automatic Tasks",
    "startup_items": "Startup Items",
}


class FindingsTable(QTableWidget):
    def __init__(self):
        super().__init__(0, 3)
        self.setHorizontalHeaderLabels(["Priority", "Area", "What AuditOS Found"])
        self.horizontalHeader().setStretchLastSection(True)

    def load_findings(self, findings):
        self.setRowCount(0)
        for f in findings:
            row = self.rowCount()
            self.insertRow(row)
            severity = str(f.get("severity", "")).title()
            area_key = str(f.get("category", ""))
            area = AREA_LABELS.get(area_key, area_key.replace("_", " ").title())
            self.setItem(row, 0, QTableWidgetItem(severity))
            self.setItem(row, 1, QTableWidgetItem(area))
            self.setItem(row, 2, QTableWidgetItem(str(f.get("detail", ""))))
