from __future__ import annotations

import json
from pathlib import Path

from PySide6.QtCore import QTimer
from PySide6.QtWidgets import (
    QFileDialog,
    QLabel,
    QHBoxLayout,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QTabWidget,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from workers import start_audit_in_thread
from ui.findings_table import FindingsTable
from ui.changes_table import ChangesTable
from ui.behavior_table import BehaviorTable
from ui.settings_dialog import SettingsDialog
from services.baseline_store import save_baseline, save_last_report, load_baseline
from services.diff_engine import build_diff
from services.crash_logger import log_message
from services.first_run_notice import show_first_run_notice
from services.network_behavior_baseline import (
    load_latest_snapshot,
    save_snapshot,
    diff_behavior,
    format_behavior_diff,
)


def format_summary_text(summary: dict, behavior_text: str = "") -> str:
    risk = str(summary.get("overall_risk", "unknown")).upper()
    counts = summary.get("counts", {})
    recs = summary.get("recommendations", [])
    findings = summary.get("top_findings", [])

    lines = [
        f"Overall Risk: {risk}",
        "",
        f"High findings:   {counts.get('high', 0)}",
        f"Medium findings: {counts.get('medium', 0)}",
        f"Low findings:    {counts.get('low', 0)}",
        "",
        "Top Findings:",
    ]

    if findings:
        for f in findings[:10]:
            lines.append(f"- [{str(f.get('severity', '')).upper()}] {f.get('detail', '')}")
    else:
        lines.append("- No findings")

    lines.append("")
    lines.append("Recommendations:")

    if recs:
        for r in recs:
            lines.append(f"- {r}")
    else:
        lines.append("- No recommendations")

    if behavior_text:
        lines.append("")
        lines.append(behavior_text)

    return "\n".join(lines)


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("AuditOS")

        self.current_report = None
        self.current_findings = []
        self.current_behavior = {
            "new_connections": [],
            "new_listening_ports": [],
            "new_extensions": [],
        }

        self.thread = None
        self.worker = None
        self.audit_running = False
        self.baseline_prompt_shown_this_session = False

        self.status = QLabel("AuditOS - System Transparency Audit Tool")

        self.quick = QPushButton("Quick Audit")
        self.deep = QPushButton("Deep Audit")
        self.baseline = QPushButton("Save Baseline")
        self.changes = QPushButton("What Changed")
        self.settings_btn = QPushButton("Settings")
        self.export_btn = QPushButton("Export Report")

        self.quick.clicked.connect(lambda: self.run_audit("quick"))
        self.deep.clicked.connect(lambda: self.run_audit("deep"))
        self.baseline.clicked.connect(self.save_current_baseline)
        self.changes.clicked.connect(self.show_changes)
        self.settings_btn.clicked.connect(self.open_settings)
        self.export_btn.clicked.connect(self.export_report)

        button_row = QHBoxLayout()
        for b in [self.quick, self.deep, self.baseline, self.changes, self.settings_btn, self.export_btn]:
            button_row.addWidget(b)

        self.findings = FindingsTable()
        self.changes_table = ChangesTable()
        self.behavior_table = BehaviorTable()

        self.details = QTextEdit()
        self.details.setReadOnly(True)

        self.tabs = QTabWidget()

        findings_tab = QWidget()
        findings_layout = QVBoxLayout(findings_tab)
        findings_layout.addWidget(self.findings)
        findings_layout.addWidget(self.details)

        changes_tab = QWidget()
        changes_layout = QVBoxLayout(changes_tab)
        changes_layout.addWidget(self.changes_table)

        behavior_tab = QWidget()
        behavior_layout = QVBoxLayout(behavior_tab)
        behavior_layout.addWidget(self.behavior_table)

        self.tabs.addTab(findings_tab, "Findings")
        self.tabs.addTab(changes_tab, "Changes")
        self.tabs.addTab(behavior_tab, "Behavior")

        layout = QVBoxLayout()
        layout.addWidget(self.status)
        layout.addLayout(button_row)
        layout.addWidget(self.tabs)

        container = QWidget()
        container.setLayout(layout)
        self.setCentralWidget(container)

        self.findings.itemSelectionChanged.connect(self.on_finding_selected)

        QTimer.singleShot(0, lambda: show_first_run_notice(self))

    def run_audit(self, mode):
        if self.audit_running:
            QMessageBox.information(self, "Audit Running", "Wait for the current scan to finish.")
            return

        log_message(f"UI requested audit mode={mode}")

        self.audit_running = True
        self.status.setText(f"Running {mode} audit...")

        self.thread, self.worker = start_audit_in_thread(mode)

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
            self.worker = None

        if self.thread:
            self.thread.deleteLater()
            self.thread = None

        self.audit_running = False

    def _maybe_prompt_to_create_baseline(self):
        try:
            if not self.current_report:
                return

            existing_baseline = load_baseline()
            if existing_baseline:
                return

            if self.baseline_prompt_shown_this_session:
                return

            self.baseline_prompt_shown_this_session = True

            reply = QMessageBox.question(
                self,
                "Create Baseline",
                "No baseline exists yet. Save this scan as your baseline?",
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.Yes,
            )

            if reply == QMessageBox.Yes:
                save_baseline(self.current_report)
                self.status.setText("Baseline created")
                log_message("Baseline created from post-scan prompt")
            else:
                log_message("User declined baseline creation prompt")

        except Exception:
            import traceback
            tb = traceback.format_exc()
            log_message(f"Baseline prompt crash:\n{tb}")
            QMessageBox.critical(self, "Crash", tb)

    def audit_finished(self, report):
        try:
            log_message("audit_finished called")

            previous = load_latest_snapshot()
            behavior = diff_behavior(report, previous)
            behavior_text = format_behavior_diff(behavior)
            save_snapshot(report)

            self.current_report = report
            self.current_report["behavior_diff"] = behavior
            self.current_behavior = behavior

            save_last_report(self.current_report)

            summary = report.get("summary", {})
            self.current_findings = summary.get("top_findings", [])

            self.status.setText(f"Risk: {summary.get('overall_risk', 'unknown').upper()}")
            self.findings.load_findings(self.current_findings)
            self.behavior_table.load_behavior(self.current_behavior)
            self.details.setPlainText(format_summary_text(summary, behavior_text))

            self._maybe_prompt_to_create_baseline()

            log_message("UI update completed")

        except Exception:
            import traceback
            tb = traceback.format_exc()
            log_message(f"audit_finished crashed:\n{tb}")
            QMessageBox.critical(self, "Crash", tb)

    def audit_failed(self, message):
        log_message(f"audit_failed: {message}")
        QMessageBox.critical(self, "Audit failed", message)

    def save_current_baseline(self):
        try:
            if not self.current_report:
                QMessageBox.information(self, "Run scan first", "Run an audit before saving baseline.")
                return

            save_baseline(self.current_report)
            self.status.setText("Baseline saved")
            self.baseline_prompt_shown_this_session = True
            log_message("Baseline saved successfully")

        except Exception:
            import traceback
            tb = traceback.format_exc()
            log_message(f"Baseline crash:\n{tb}")
            QMessageBox.critical(self, "Crash", tb)

    def show_changes(self):
        try:
            if not self.current_report:
                QMessageBox.information(self, "Run scan first", "Run an audit before comparing changes.")
                return

            baseline = load_baseline()
            if not baseline:
                QMessageBox.information(self, "No baseline", "Save a baseline first.")
                return

            diff = build_diff(baseline["report"], self.current_report)
            self.changes_table.load_changes(diff["changes"])
            log_message(f"Displayed {diff['count']} baseline changes")
            self.tabs.setCurrentIndex(1)

        except Exception:
            import traceback
            tb = traceback.format_exc()
            log_message(f"show_changes crash:\n{tb}")
            QMessageBox.critical(self, "Crash", tb)

    def on_finding_selected(self):
        row = self.findings.currentRow()
        if row < 0 or row >= len(self.current_findings):
            return

        self.details.setPlainText(json.dumps(self.current_findings[row], indent=2))

    def export_report(self):
        if not self.current_report:
            QMessageBox.information(self, "No report", "Run an audit first.")
            return

        path, _ = QFileDialog.getSaveFileName(
            self,
            "Export Report",
            "audit_report.json",
            "JSON Files (*.json)",
        )

        if not path:
            return

        Path(path).write_text(
            json.dumps(self.current_report, indent=2),
            encoding="utf-8",
        )

        log_message(f"Report exported to {path}")
        QMessageBox.information(self, "Exported", f"Saved report to {path}")

    def open_settings(self):
        SettingsDialog(self).exec()