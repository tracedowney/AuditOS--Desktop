from PySide6.QtCore import Qt
from PySide6.QtWidgets import QHeaderView, QTableWidget, QTableWidgetItem


def _friendly_item_name(name: str) -> str:
    known = {
        "backgroundtaskhost.exe": "Windows background task host",
        "chrome.exe": "Google Chrome",
        "code.exe": "Visual Studio Code",
        "firefox.exe": "Mozilla Firefox",
        "lsass.exe": "Windows security service",
        "msedge.exe": "Microsoft Edge",
        "onedrive.exe": "Microsoft OneDrive",
        "prl_tools_service.exe": "Parallels Tools service",
        "services.exe": "Windows services manager",
        "spoolsv.exe": "Windows print spooler",
        "svchost.exe": "Windows service host",
        "system": "Windows System",
        "teams.exe": "Microsoft Teams",
        "wininit.exe": "Windows startup service",
    }
    key = str(name).strip().lower()
    return known.get(key, str(name))


def _normality_label(name: str) -> str:
    standard = {
        "backgroundtaskhost.exe",
        "lsass.exe",
        "prl_tools_service.exe",
        "services.exe",
        "spoolsv.exe",
        "svchost.exe",
        "system",
        "wininit.exe",
    }
    key = str(name).strip().lower()
    return "Likely standard background activity" if key in standard else "Worth recognizing and confirming"


def _connection_target(addr: str, port: int) -> str:
    if not addr:
        return "an unknown destination"
    if addr.startswith(("127.", "192.168.", "10.", "172.16.", "::1", "fe80:")):
        return f"a device or service on your local network ({addr})"
    if int(port) in {80, 443, 8080, 8443}:
        return f"a web service on the internet ({addr})"
    if int(port) in {53, 853}:
        return f"a DNS service ({addr})"
    return f"a public internet address ({addr})"


def _listening_meaning(name: str, port: int) -> str:
    standard_ports = {
        135: "Windows service coordination",
        139: "Windows file or printer sharing",
        445: "Windows file or printer sharing",
        5040: "Windows background service communication",
    }
    normality = _normality_label(name)
    if int(port) in standard_ports:
        return f"{normality}. Listening means this program is waiting for another app or device to contact it, usually for {standard_ports[int(port)]}."
    if 49152 <= int(port) <= 65535:
        return f"{normality}. Listening means this program is waiting for another app or Windows service to contact it on an internal communication port."
    return f"{normality}. Listening means this program is waiting for another app or device to contact it on port {port}."


class BehaviorTable(QTableWidget):
    def __init__(self):
        super().__init__(0, 3)
        self.setHorizontalHeaderLabels(["What Changed", "Program or Item", "Plain-English Meaning"])
        self.verticalHeader().setVisible(False)
        self.setWordWrap(False)
        header = self.horizontalHeader()
        header.setDefaultAlignment(Qt.AlignLeft | Qt.AlignVCenter)
        header.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.Stretch)

    def load_behavior(self, behavior):
        self.setRowCount(0)
        connections = behavior.get("new_connections") or behavior.get("current_connections", [])
        listening_ports = behavior.get("new_listening_ports") or behavior.get("current_listening_ports", [])

        for name, port, addr in connections:
            row = self.rowCount()
            self.insertRow(row)
            friendly = _friendly_item_name(str(name))
            self.setItem(row, 0, QTableWidgetItem("New Internet Activity"))
            self.setItem(row, 1, QTableWidgetItem(friendly))
            self.setItem(
                row,
                2,
                QTableWidgetItem("Click this row to read the full explanation below."),
            )
            self.item(row, 2).setToolTip(
                f"{_normality_label(str(name))}. {friendly} connected to {_connection_target(str(addr), int(port))} on port {port} since the last scan."
            )

        for name, port in listening_ports:
            row = self.rowCount()
            self.insertRow(row)
            friendly = _friendly_item_name(str(name))
            self.setItem(row, 0, QTableWidgetItem("New Open Port"))
            self.setItem(row, 1, QTableWidgetItem(friendly))
            self.setItem(row, 2, QTableWidgetItem("Click this row to read the full explanation below."))
            self.item(row, 2).setToolTip(_listening_meaning(str(name), int(port)))

        for browser, ext_id in behavior.get("new_extensions", []):
            row = self.rowCount()
            self.insertRow(row)
            self.setItem(row, 0, QTableWidgetItem("New Extension"))
            self.setItem(row, 1, QTableWidgetItem(str(browser)))
            self.setItem(row, 2, QTableWidgetItem("Click this row to read the full explanation below."))
            self.item(row, 2).setToolTip(f"Browser extension ID observed: {ext_id}")

        for server in behavior.get("new_dns_servers", []):
            row = self.rowCount()
            self.insertRow(row)
            self.setItem(row, 0, QTableWidgetItem("New DNS Server"))
            self.setItem(row, 1, QTableWidgetItem(str(server)))
            self.setItem(row, 2, QTableWidgetItem("Click this row to read the full explanation below."))
            self.item(row, 2).setToolTip("A new DNS server appeared compared with the last scan")

        for item in behavior.get("new_startup_items", []):
            row = self.rowCount()
            self.insertRow(row)
            self.setItem(row, 0, QTableWidgetItem("New Startup Item"))
            self.setItem(row, 1, QTableWidgetItem(str(item)))
            self.setItem(row, 2, QTableWidgetItem("Click this row to read the full explanation below."))
            self.item(row, 2).setToolTip("This item can start automatically and was not in the last scan")

        for task in behavior.get("new_scheduled_tasks", []):
            row = self.rowCount()
            self.insertRow(row)
            self.setItem(row, 0, QTableWidgetItem("New Scheduled Task"))
            self.setItem(row, 1, QTableWidgetItem(str(task)))
            self.setItem(row, 2, QTableWidgetItem("Click this row to read the full explanation below."))
            self.item(row, 2).setToolTip("This scheduled task appeared after the previous scan")

        if self.rowCount() == 0:
            self.insertRow(0)
            self.setItem(0, 0, QTableWidgetItem("Info"))
            self.setItem(0, 1, QTableWidgetItem("Behavior"))
            if behavior.get("has_previous"):
                detail = "No behavior worth highlighting right now compared with the previous scan."
            else:
                detail = "No previous scan snapshot yet. Run another scan later to compare behavior."
            self.setItem(0, 2, QTableWidgetItem(detail))
            self.item(0, 2).setToolTip(detail)
