from __future__ import annotations

import json
from pathlib import Path

from PySide6.QtCore import QTimer, Slot
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


def _risk_color(risk: str) -> str:
    return {
        "LOW": "#188038",
        "MEDIUM": "#b26a00",
        "HIGH": "#b00020",
    }.get(risk, "#444444")


def format_summary_html(summary: dict, mode: str = "") -> str:
    risk = str(summary.get("overall_risk", "unknown")).upper()
    counts = summary.get("counts", {})
    recs = summary.get("recommendations", [])
    limitations = summary.get("limitations", [])
    plain_summary = summary.get("plain_summary", [])
    risk_color = _risk_color(risk)

    summary_lines = "".join(
        f"<li>{line}</li>" for line in plain_summary
    ) or "<li>AuditOS is still gathering enough context to describe this scan.</li>"

    recommendation_lines = "".join(
        f"<li>{rec}</li>" for rec in recs
    ) or "<li>No immediate recommendations from this scan.</li>"

    limitation_block = ""
    if limitations:
        limitation_items = "".join(f"<li>{note}</li>" for note in limitations)
        limitation_block = (
            "<div style='margin-top:16px;'>"
            "<div style='font-size:15px;font-weight:700;color:#5f6368;margin-bottom:6px;'>Environment Notes</div>"
            f"<ul style='margin:0 0 0 18px;'>{limitation_items}</ul>"
            "</div>"
        )

    mode_label = ""
    if mode:
        pretty_mode = "Quick Audit" if str(mode).lower() == "quick" else "Deep Audit" if str(mode).lower() == "deep" else str(mode)
        mode_label = f"<div style='font-size: 16px; font-weight: 700; color: #5f6368; margin-bottom: 10px;'>{pretty_mode}</div>"

    return f"""
    <div style="font-family: 'Segoe UI', sans-serif; color: #202124; line-height: 1.45;">
      <div style="font-size: 28px; font-weight: 800; margin-bottom: 6px;">AuditOS Scorecard</div>
      {mode_label}
      <div style="font-size: 24px; font-weight: 800; color: {risk_color}; margin-bottom: 18px;">Overall Risk: {risk}</div>

      <div style="display: block; margin-bottom: 18px;">
        <div style="font-size: 16px; font-weight: 700; margin-bottom: 8px;">Summary Numbers</div>
        <div style="margin-left: 4px;">
          <div><b>High:</b> {counts.get('high', 0)}</div>
          <div><b>Medium:</b> {counts.get('medium', 0)}</div>
          <div><b>Low:</b> {counts.get('low', 0)}</div>
        </div>
      </div>

      <div style="margin-bottom: 16px;">
        <div style="font-size: 16px; font-weight: 700; margin-bottom: 6px;">What Stands Out</div>
        <ul style="margin: 0 0 0 18px;">{summary_lines}</ul>
      </div>

      <div style="margin-bottom: 12px;">
        <div style="font-size: 16px; font-weight: 700; margin-bottom: 6px;">Recommended Next Steps</div>
        <ul style="margin: 0 0 0 18px;">{recommendation_lines}</ul>
      </div>

      {limitation_block}
    </div>
    """


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
        self.details.setMinimumHeight(250)

        self.tabs = QTabWidget()

        tab1 = QWidget()
        l1 = QVBoxLayout(tab1)
        l1.addWidget(self.details)
        l1.addWidget(self.findings)

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
        self.worker.progress.connect(self.update_progress_text)

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

    @Slot(str)
    def update_progress_text(self, message: str):
        self.details.setPlainText(message)

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
            mode = str(report.get("meta", {}).get("mode", ""))
            self.details.setHtml(format_summary_html(summary, mode))
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
        finding = self.current_findings[row]
        self.status.setText(
            f"Selected finding: {str(finding.get('severity', '')).upper()} | {finding.get('detail', '')}"
        )

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
