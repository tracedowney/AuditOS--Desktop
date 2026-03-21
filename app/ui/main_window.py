from __future__ import annotations

import json
from pathlib import Path

from PySide6.QtCore import QTimer, Slot
from PySide6.QtWidgets import (
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QTabWidget,
    QTextEdit,
    QToolButton,
    QVBoxLayout,
    QWidget,
)

from workers import start_audit_in_thread
from ui.findings_table import FindingsTable
from ui.changes_table import ChangesTable
from ui.behavior_table import BehaviorTable
from ui.settings_dialog import SettingsDialog
from services.baseline_store import save_baseline, save_last_report, load_baseline
from services.baseline_store import load_last_report, load_settings
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
    counts = summary.get("counts", {})
    recs = summary.get("recommendations", [])
    limitations = summary.get("limitations", [])
    plain_summary = summary.get("plain_summary", [])

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
      {mode_label}

      <div style="display: block; margin-bottom: 18px;">
        <div style="font-size: 16px; font-weight: 700; margin-bottom: 8px;">Total Findings</div>
        <div style="margin-left: 4px;">
          <div><b>High:</b> {counts.get('high', 0)}</div>
          <div><b>Medium:</b> {counts.get('medium', 0)}</div>
          <div><b>Low:</b> {counts.get('low', 0)}</div>
        </div>
      </div>

      <div style="margin-bottom: 16px;">
        <div style="font-size: 16px; font-weight: 700; margin-bottom: 6px;">Notable Findings</div>
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
        self.setStyleSheet(
            """
            QMainWindow {
                background: #f6f7f4;
            }
            QWidget {
                background: #f6f7f4;
                color: #202124;
            }
            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #6fbe63, stop:0.48 #4b9e46, stop:1 #2f6e2d);
                border: 1px solid #2f6e2d;
                border-bottom: 3px solid #204b20;
                border-radius: 14px;
                padding: 11px 18px 9px 18px;
                min-height: 20px;
                font-weight: 600;
                color: #ffffff;
            }
            QPushButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #7bcb6f, stop:0.48 #58ad52, stop:1 #367b34);
                border-color: #2c642a;
            }
            QPushButton:pressed {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #2f6e2d, stop:1 #4a9445);
                padding-top: 12px;
                padding-bottom: 8px;
            }
            QPushButton:disabled {
                background: #c6d4c1;
                color: #eef3eb;
                border-color: #a9b7a3;
            }
            QTabWidget::pane {
                border: 1px solid #d9e0d5;
                border-radius: 14px;
                background: #fbfcf9;
                top: -1px;
            }
            QTabBar::tab {
                background: #e9eee5;
                border: 1px solid #d9e0d5;
                border-bottom: none;
                border-top-left-radius: 10px;
                border-top-right-radius: 10px;
                padding: 10px 16px;
                margin-right: 6px;
                color: #4f5b50;
                font-weight: 600;
            }
            QTabBar::tab:selected {
                background: #fbfcf9;
                color: #1f2a1f;
            }
            QTabBar::tab:hover:!selected {
                background: #f1f5ee;
            }
            QToolButton {
                background: #eef5ea;
                border: 1px solid #c9d8c3;
                border-radius: 12px;
                font-weight: 700;
                color: #2f5d31;
                padding: 2px 0;
            }
            QToolButton:hover {
                background: #dfead8;
            }
            QTextEdit, QTableWidget {
                background: #ffffff;
                border: 1px solid #d9e0d5;
                border-radius: 14px;
            }
            QHeaderView::section {
                background: #f0f4ec;
                color: #334033;
                border: none;
                border-bottom: 1px solid #d9e0d5;
                padding: 8px 10px;
                font-weight: 700;
            }
            """
        )

        self.current_report = None
        self.current_findings = []
        self.current_behavior = {}
        self.previous_report = None

        self.thread = None
        self.worker = None
        self.audit_running = False
        self.last_limitations_signature = ""
        self.schedule_timer = QTimer(self)
        self.schedule_timer.setSingleShot(True)
        self.schedule_timer.timeout.connect(self.run_scheduled_audit)

        self.status = QLabel("AuditOS - System Transparency Audit Tool")
        self.scorecard_title = QLabel("AuditOS Scorecard")
        self.scorecard_risk = QLabel("Overall Risk: UNKNOWN")
        self.scorecard_title.setStyleSheet("font-size: 28px; font-weight: 800; color: #202124;")
        self.scorecard_risk.setStyleSheet("font-size: 22px; font-weight: 800; color: #444444;")

        self.quick = QPushButton("Quick Audit")
        self.deep = QPushButton("Deep Audit")
        self.baseline = QPushButton("Save Baseline")
        self.settings_btn = QPushButton("Settings")
        self.export_btn = QPushButton("Export Report")

        self.quick.clicked.connect(lambda: self.run_audit("quick"))
        self.deep.clicked.connect(lambda: self.run_audit("deep"))
        self.baseline.clicked.connect(self.save_current_baseline)
        self.settings_btn.clicked.connect(self.open_settings)
        self.export_btn.clicked.connect(self.export_report)

        button_row = QHBoxLayout()
        for b in [self.quick, self.deep, self.baseline, self.settings_btn, self.export_btn]:
            button_row.addWidget(b)

        self.findings = FindingsTable()
        self.changes_table = ChangesTable()
        self.behavior_table = BehaviorTable()

        self.details = QTextEdit()
        self.details.setReadOnly(True)
        self.details.setMinimumHeight(250)
        self.behavior_detail = QLabel("Select a behavior item to read the full explanation.")
        self.behavior_detail.setWordWrap(True)
        self.behavior_detail.setStyleSheet("color: #5f6368; padding: 8px 4px;")

        scorecard_header = QHBoxLayout()
        scorecard_header.addWidget(self.scorecard_title)
        scorecard_header.addStretch(1)
        scorecard_header.addWidget(self.scorecard_risk)

        self.changes_info_label = QLabel(
            "Changes compares this scan to your saved baseline or previous scan so you can see what appeared, disappeared, or changed."
        )
        self.changes_state_label = QLabel(
            "Run a scan, then AuditOS will compare it to your saved baseline or previous scan here."
        )
        self.behavior_info_label = QLabel(
            "Behavior highlights internet activity, open ports, startup items, scheduled tasks, and extensions. Startup items and scheduled tasks are programs or jobs that can run automatically."
        )
        for label in [self.changes_info_label, self.behavior_info_label, self.changes_state_label]:
            label.setWordWrap(True)
            label.setVisible(False)
            label.setStyleSheet("color: #5f6368; padding: 6px 8px;")
        self.changes_info_label.setVisible(True)
        self.changes_state_label.setVisible(True)

        self.changes_info_btn = self._make_info_button(self.changes_info_label)
        self.behavior_info_btn = self._make_info_button(self.behavior_info_label)

        self.tabs = QTabWidget()

        tab1 = QWidget()
        l1 = QVBoxLayout(tab1)
        l1.addLayout(scorecard_header)
        l1.addWidget(self.details)
        l1.addWidget(self.findings)

        tab2 = QWidget()
        l2 = QVBoxLayout(tab2)
        l2.addLayout(self._build_info_row("About Changes", self.changes_info_btn))
        l2.addWidget(self.changes_info_label)
        l2.addWidget(self.changes_state_label)
        l2.addWidget(self.changes_table)

        tab3 = QWidget()
        l3 = QVBoxLayout(tab3)
        l3.addLayout(self._build_info_row("About Behavior", self.behavior_info_btn))
        l3.addWidget(self.behavior_info_label)
        l3.addWidget(self.behavior_table)
        l3.addWidget(self.behavior_detail)

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
        self.behavior_table.itemSelectionChanged.connect(self.on_behavior_selected)
        self.changes_table.load_changes([])
        self.refresh_changes_preview()
        self.configure_schedule()

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

    def _make_info_button(self, target: QLabel) -> QToolButton:
        button = QToolButton()
        button.setText("i")
        button.setToolTip("Show more information")
        button.setFixedWidth(24)
        button.clicked.connect(lambda: target.setVisible(not target.isVisible()))
        return button

    def _build_info_row(self, title: str, button: QToolButton) -> QHBoxLayout:
        row = QHBoxLayout()
        label = QLabel(title)
        label.setStyleSheet("font-weight: 700; color: #202124;")
        row.addWidget(label)
        row.addWidget(button)
        row.addStretch(1)
        return row

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
            self.refresh_changes_preview()

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
            overall_risk = str(summary.get("overall_risk", "unknown")).upper()

            status_text = f"Risk: {overall_risk}"
            if limitations:
                status_text += f" | Limited visibility: {len(limitations)}"

            self.status.setText(status_text)
            self.scorecard_risk.setText(f"Overall Risk: {overall_risk}")
            self.scorecard_risk.setStyleSheet(
                f"font-size: 22px; font-weight: 800; color: {_risk_color(overall_risk)};"
            )
            self.findings.load_findings(self.current_findings)
            self.behavior_table.load_behavior(self.current_behavior)
            mode = str(report.get("meta", {}).get("mode", ""))
            self.details.setHtml(format_summary_html(summary, mode))
            self.maybe_explain_limitations(limitations)
            self.refresh_changes_preview()
            self.configure_schedule()

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
            self.refresh_changes_preview()

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
                self.changes_info_label.setText(
                    f"AuditOS compared this scan with your {comparison_label} and did not find any new changes to call out."
                )
                self.changes_info_label.setVisible(True)
                self.status.setText(f"No changes vs {comparison_label}")
            else:
                self.changes_info_label.setText(
                    f"AuditOS found {diff['count']} change(s) compared with your {comparison_label}. Review the table below for what changed and why it matters."
                )
                self.changes_info_label.setVisible(True)
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

    def on_behavior_selected(self):
        row = self.behavior_table.currentRow()
        if row < 0:
            return
        item = self.behavior_table.item(row, 2)
        if not item:
            return
        self.behavior_detail.setText(item.toolTip() or item.text())

    def refresh_changes_preview(self):
        if not self.current_report:
            self.changes_info_label.setText(
                "Run a scan, then AuditOS will compare it to your saved baseline or previous scan here."
            )
            self.changes_state_label.setText("No scan has been compared yet.")
            self.changes_state_label.setVisible(True)
            self.changes_table.load_changes([])
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

        if not comparison_report:
            self.changes_info_label.setText(
                "Save a baseline or run another scan and AuditOS will show what changed here."
            )
            self.changes_state_label.setText(
                "No comparison source is available yet. Save a baseline or run another scan."
            )
            self.changes_state_label.setVisible(True)
            self.changes_table.load_changes([])
            return

        diff = build_diff(comparison_report, self.current_report)
        self.changes_table.load_changes(diff["changes"])
        if diff["count"] == 0:
            self.changes_info_label.setText(
                f"AuditOS compared this scan with your {comparison_label} and did not find any new changes to call out."
            )
            self.changes_state_label.setText("No new changes were detected.")
            self.changes_state_label.setVisible(True)
        else:
            self.changes_info_label.setText(
                f"AuditOS found {diff['count']} change(s) compared with your {comparison_label}. Review the table below for what changed and why it matters."
            )
            self.changes_state_label.setVisible(False)

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
        dialog = SettingsDialog(self)
        if dialog.exec():
            self.configure_schedule()

    def configure_schedule(self):
        settings = load_settings()
        if not settings.get("schedule_enabled"):
            self.schedule_timer.stop()
            return

        frequency = str(settings.get("schedule_frequency", "weekly")).lower()
        interval_map = {
            "daily": 24 * 60 * 60 * 1000,
            "weekly": 7 * 24 * 60 * 60 * 1000,
            "monthly": 30 * 24 * 60 * 60 * 1000,
        }
        interval_ms = interval_map.get(frequency, interval_map["weekly"])
        self.schedule_timer.start(interval_ms)
        log_message(
            f"Scheduled scans enabled: mode={settings.get('schedule_mode', 'quick')} frequency={frequency}"
        )

    def run_scheduled_audit(self):
        settings = load_settings()
        if self.audit_running:
            self.schedule_timer.start(15 * 60 * 1000)
            log_message("Scheduled scan delayed because another audit is running")
            return

        mode = str(settings.get("schedule_mode", "quick")).lower()
        log_message(f"Starting scheduled audit mode={mode}")
        self.run_audit(mode)
