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
from services.baseline_store import load_last_report
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
    limitations = summary.get("limitations", [])

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

    if limitations:
        lines.append("")
        lines.append("Environment Notes:")
        for note in limitations:
            lines.append(f"- {note}")

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
        self.current_behavior = {}
        self.previous_report = None

        self.thread = None
        self.worker = None
        self.audit_running = False
        self.last_limitations_signature = ""

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

        tab1 = QWidget()
        l1 = QVBoxLayout(tab1)
        l1.addWidget(self.findings)
        l1.addWidget(self.details)

        tab2 = QWidget()
        l2 = QVBoxLayout(tab2)
        l2.addWidget(self.changes_table)

        tab3 = QWidget()
        l3 = QVBoxLayout(tab3)
        l3.addWidget(self.behavior_table)

        self.tabs.addTab(tab1, "Findings")
        self.tabs.addTab(tab2, "Changes")
        self.tabs.addTab(tab3, "Behavior")

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

    def maybe_prompt_for_baseline(self):
        baseline = load_baseline()
        if baseline:
            return

        box = QMessageBox(self)
        box.setWindowTitle("No baseline saved yet")
        box.setText(
            "AuditOS can compare future scans against a saved baseline to show what changed over time.\n\n"
            "Would you like to save this audit as your baseline?"
        )

        save_btn = box.addButton("Save Baseline", QMessageBox.AcceptRole)
        box.addButton("Not Now", QMessageBox.RejectRole)
        box.exec()

        if box.clickedButton() == save_btn and self.current_report:
            save_baseline(self.current_report)
            self.status.setText("Baseline saved")
            log_message("Baseline saved from first-run prompt")

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

            last_report = load_last_report()
            self.previous_report = last_report.get("report") if isinstance(last_report, dict) else None
            save_last_report(self.current_report)

            summary = report.get("summary", {})
            self.current_findings = summary.get("top_findings", [])
            limitations = summary.get("limitations", [])

            status_text = f"Risk: {summary.get('overall_risk', 'unknown').upper()}"
            if limitations:
                status_text += f" | Limited visibility: {len(limitations)}"

            self.status.setText(status_text)
            self.findings.load_findings(self.current_findings)
            self.behavior_table.load_behavior(self.current_behavior)
            self.details.setPlainText(format_summary_text(summary, behavior_text))
            self.maybe_explain_limitations(limitations)

            self.maybe_prompt_for_baseline()

            log_message("UI update completed")

        except Exception:
            import traceback
            tb = traceback.format_exc()
            log_message(f"audit_finished crashed:\n{tb}")
            QMessageBox.critical(self, "Crash", tb)

    def audit_failed(self, message):
        log_message(f"audit_failed: {message}")
        QMessageBox.critical(self, "Audit failed", message)

    def maybe_explain_limitations(self, limitations):
        if not limitations:
            self.last_limitations_signature = ""
            return

        signature = "\n".join(limitations)
        if signature == self.last_limitations_signature:
            return

        self.last_limitations_signature = signature
        QMessageBox.information(
            self,
            "Limited Audit Visibility",
            "AuditOS completed the scan, but parts of this system limited what could be inspected.\n\n"
            "The details panel includes environment notes so you can see which areas had reduced visibility.",
        )

    def save_current_baseline(self):
        try:
            if not self.current_report:
                QMessageBox.information(self, "Run scan first", "Run an audit before saving baseline.")
                return

            save_baseline(self.current_report)
            self.status.setText("Baseline saved")
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
            comparison_report = None
            comparison_label = ""
            if baseline and isinstance(baseline.get("report"), dict):
                comparison_report = baseline["report"]
                comparison_label = "saved baseline"
            elif self.previous_report:
                comparison_report = self.previous_report
                comparison_label = "previous scan"
            else:
                QMessageBox.information(
                    self,
                    "No comparison report",
                    "Run at least two scans or save a baseline so AuditOS has something to compare against."
                )
                return

            diff = build_diff(comparison_report, self.current_report)
            self.changes_table.load_changes(diff["changes"])
            self.tabs.setCurrentIndex(1)
            if diff["count"] == 0:
                self.status.setText(f"No changes vs {comparison_label}")
            else:
                self.status.setText(f"{diff['count']} change(s) vs {comparison_label}")
            log_message(f"Displayed {diff['count']} changes against {comparison_label}")

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
