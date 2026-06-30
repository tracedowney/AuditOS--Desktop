from PySide6.QtCore import Qt
from PySide6.QtWidgets import QHeaderView, QTableWidget, QTableWidgetItem


AREA_LABELS = {
    "active_connections": "Internet Connections",
    "background_tasks": "Background Tasks",
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
        self.verticalHeader().setVisible(False)
        self.setWordWrap(True)
        header = self.horizontalHeader()
        header.setDefaultAlignment(Qt.AlignLeft | Qt.AlignVCenter)
        header.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.Stretch)

    def load_findings(self, findings):
        self.setRowCount(0)
        for f in findings:
            row = self.rowCount()
            self.insertRow(row)
            severity = str(f.get("severity", "")).title()
            area_key = str(f.get("category", ""))
            area = AREA_LABELS.get(area_key, area_key.replace("_", " ").title())
            priority_item = QTableWidgetItem(severity)
            area_item = QTableWidgetItem(area)
            detail_item = QTableWidgetItem(str(f.get("detail", "")))

            evidence = f.get("evidence") if isinstance(f.get("evidence"), dict) else {}
            tooltip_parts = [str(f.get("detail", ""))]
            explanation = str(evidence.get("explanation", "")).strip()
            impact_hint = str(evidence.get("impact_hint", "")).strip()
            exe = str(evidence.get("exe", "")).strip()
            cmdline_preview = str(evidence.get("cmdline_preview", "")).strip()

            if explanation:
                tooltip_parts.append(explanation)
            if impact_hint:
                tooltip_parts.append(f"Possible impact: {impact_hint}")
            if exe:
                tooltip_parts.append(f"Path: {exe}")
            if cmdline_preview:
                tooltip_parts.append(f"Command: {cmdline_preview}")

            tooltip = "\n\n".join(part for part in tooltip_parts if part)
            priority_item.setToolTip(tooltip)
            area_item.setToolTip(tooltip)
            detail_item.setToolTip(tooltip)

            self.setItem(row, 0, priority_item)
            self.setItem(row, 1, area_item)
            self.setItem(row, 2, detail_item)

        self.resizeRowsToContents()
