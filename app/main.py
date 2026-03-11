from __future__ import annotations
import sys
from PySide6.QtWidgets import QApplication
from services.crash_logger import install_global_exception_hook, log_message
from ui.main_window import MainWindow

def main() -> int:
    install_global_exception_hook()
    log_message("Application starting")

    app = QApplication(sys.argv)
    app.setApplicationName("AuditOS")
    app.setOrganizationName("AuditOS")

    window = MainWindow()
    window.resize(1150, 800)
    window.show()

    exit_code = app.exec()
    log_message(f"Application exiting with code {exit_code}")
    return exit_code

if __name__ == "__main__":
    raise SystemExit(main())
