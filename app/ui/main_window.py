from __future__ import annotations
import json
from pathlib import Path

from PySide6.QtWidgets import (
    QMainWindow,
    QLabel,
    QPushButton,
    QVBoxLayout,
    QHBoxLayout,
    QWidget,
    QTextEdit,
    QTabWidget,
    QFileDialog,
    QMessageBox,
)

from workers import start_audit_in_thread
from ui.findings_table import FindingsTable
from ui.changes_table import ChangesTable
from ui.settings_dialog import SettingsDialog
from services.baseline_store import save_baseline, save_last_report, load_baseline, load_settings
from services.diff_engine import build_diff
from services.ai_explainer import explain_finding_locally
from services.crash_logger import log_message


class MainWindow(QMainWindow):

    def __init__(self):
        super().__init__()

        self.setWindowTitle("AuditOS")

        self.current_report = None
        self.current_findings = []

        self.thread = None
        self.worker = None
        self.audit_running = False

        self.status = QLabel("AuditOS - System Transparency Audit Tool")

        self.quick = QPushButton("Quick Audit")
        self.deep = QPushButton("Deep Audit")
        self.baseline = QPushButton("Save Baseline")
        self.changes = QPushButton("What Changed")
        self.explain = QPushButton("")
        self.settings_btn = QPushButton("Settings")
        self.export_btn = QPushButton("Export Report")

        self.quick.clicked.connect(lambda: self.run_audit("quick"))
        self.deep.clicked.connect(lambda: self.run_audit("deep"))
        self.baseline.clicked.connect(self.save_current_baseline)
        self.changes.clicked.connect(self.show_changes)
        self.explain.clicked.connect(self.explain_top_finding)
        self.settings_btn.clicked.connect(self.open_settings)
        self.export_btn.clicked.connect(self.export_report)

        button_row = QHBoxLayout()
        for b in [self.quick,self.deep,self.baseline,self.changes,self.explain,self.settings_btn,self.export_btn]:
            button_row.addWidget(b)

        self.findings = FindingsTable()
        self.changes_table = ChangesTable()

        self.details = QTextEdit()
        self.details.setReadOnly(True)

        tabs = QTabWidget()

        tab1 = QWidget()
        l1 = QVBoxLayout(tab1)
        l1.addWidget(self.findings)
        l1.addWidget(self.details)

        tab2 = QWidget()
        l2 = QVBoxLayout(tab2)
        l2.addWidget(self.changes_table)

        tabs.addTab(tab1,"Findings")
        tabs.addTab(tab2,"Changes")

        layout = QVBoxLayout()
        layout.addWidget(self.status)
        layout.addLayout(button_row)
        layout.addWidget(tabs)

        container = QWidget()
        container.setLayout(layout)

        self.setCentralWidget(container)

        self.findings.itemSelectionChanged.connect(self.on_finding_selected)

    def run_audit(self,mode):

        if self.audit_running:
            QMessageBox.information(self,"Audit Running","Wait for the current scan to finish.")
            return

        log_message(f"UI requested audit mode={mode}")

        self.audit_running = True
        self.status.setText(f"Running {mode} audit...")

        self.thread,self.worker = start_audit_in_thread(mode)

        self.worker.finished.connect(self.audit_finished)
        self.worker.failed.connect(self.audit_failed)
        self.worker.progress.connect(self.details.setPlainText)

        self.worker.finished.connect(self.thread.quit)
        self.worker.failed.connect(self.thread.quit)

        self.thread.finished.connect(self.cleanup_thread)

        self.thread.start()

    def cleanup_thread(self):

        log_message("Cleaning up worker thread")

        if self.worker:
            self.worker.deleteLater()
            self.worker=None

        if self.thread:
            self.thread.deleteLater()
            self.thread=None

        self.audit_running=False

    def audit_finished(self,report):

        try:

            log_message("audit_finished called")

            self.current_report=report

            save_last_report(report)

            summary=report.get("summary",{})

            self.current_findings=summary.get("top_findings",[])

            self.status.setText(
                f"Risk: {summary.get('overall_risk','unknown')}"
            )

            self.findings.load_findings(self.current_findings)

            self.details.setPlainText(
                json.dumps(summary,indent=2)
            )

            log_message("UI update completed")

        except Exception as exc:

            import traceback
            tb=traceback.format_exc()

            log_message(f"audit_finished crashed:\n{tb}")

            QMessageBox.critical(self,"Crash",tb)

    def audit_failed(self,message):

        log_message(f"audit_failed: {message}")

        QMessageBox.critical(self,"Audit failed",message)

    def save_current_baseline(self):

        try:

            if not self.current_report:
                QMessageBox.information(self,"Run scan first","Run an audit before saving baseline.")
                return

            save_baseline(self.current_report)

            self.status.setText("Baseline saved")

            log_message("Baseline saved successfully")

        except Exception:

            import traceback
            tb=traceback.format_exc()
            log_message(f"Baseline crash:\n{tb}")
            QMessageBox.critical(self,"Crash",tb)

    def show_changes(self):

        try:

            if not self.current_report:
                QMessageBox.information(self,"Run scan first","Run an audit before comparing changes.")
                return

            baseline=load_baseline()

            if not baseline:
                QMessageBox.information(self,"No baseline","Save a baseline first.")
                return

            diff=build_diff(
                baseline["report"],
                self.current_report
            )

            self.changes_table.load_changes(diff["changes"])

            log_message(f"Displayed {diff['count']} baseline changes")

        except Exception:

            import traceback
            tb=traceback.format_exc()
            log_message(f"show_changes crash:\n{tb}")
            QMessageBox.critical(self,"Crash",tb)

    def explain_top_finding(self):

        if not self.current_findings:
            QMessageBox.information(self,"No finding","Run an audit first.")
            return

        settings=load_settings()

        text=explain_finding_locally(self.current_findings[0])

        if settings.get("license_tier")!="premium" or not settings.get("ai_enabled"):
            text+="\n\nAI explanation disabled."

        self.details.setPlainText(text)

    def on_finding_selected(self):

        row=self.findings.currentRow()

        if row<0 or row>=len(self.current_findings):
            return

        self.details.setPlainText(
            json.dumps(self.current_findings[row],indent=2)
        )

    def export_report(self):

        if not self.current_report:
            QMessageBox.information(self,"No report","Run an audit first.")
            return

        path,_=QFileDialog.getSaveFileName(
            self,
            "Export Report",
            "audit_report.json",
            "JSON Files (*.json)"
        )

        if not path:
            return

        Path(path).write_text(
            json.dumps(self.current_report,indent=2),
            encoding="utf-8"
        )

        log_message(f"Report exported to {path}")

        QMessageBox.information(self,"Exported",f"Saved report to {path}")

    def open_settings(self):
        SettingsDialog(self).exec()


