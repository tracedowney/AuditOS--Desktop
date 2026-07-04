from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from PySide6.QtCore import Qt, QTimer, QUrl, Slot
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import (
    QApplication,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QSplitter,
    QTabWidget,
    QTextEdit,
    QToolButton,
    QVBoxLayout,
    QWidget,
)

from workers import start_audit_in_thread
from ui.background_tasks_table import BackgroundTasksTable
from ui.findings_table import FindingsTable
from ui.changes_table import ChangesTable
from ui.behavior_table import BehaviorTable
from ui.settings_dialog import SettingsDialog
from services.baseline_store import save_baseline, save_last_report, load_baseline
from services.baseline_store import load_last_report, load_settings, save_settings
from services.diff_engine import build_diff
from services.crash_logger import log_message
from services.first_run_notice import show_first_run_notice
from services.report_export import default_report_filename
from services.network_behavior_baseline import (
    load_latest_snapshot,
    save_snapshot,
    diff_behavior,
    format_behavior_diff,
)
from services.schedule_state import (
    delay_schedule_until,
    ensure_schedule_next_run,
    is_schedule_due,
    mark_schedule_completed,
    next_schedule_timer_ms,
    parse_schedule_timestamp,
)
from services.update_checker import (
    RELEASES_PAGE_URL,
    UpdateCheckError,
    UpdateCheckResult,
    check_for_updates as perform_update_check,
)
from services.visibility_guidance import build_visibility_guidance
from version_info import APP_VERSION


def _risk_color(risk: str) -> str:
    return {
        "LOW": "#188038",
        "MEDIUM": "#b26a00",
        "HIGH": "#b00020",
    }.get(risk, "#444444")


def _format_release_date(value: str) -> str:
    label = str(value).strip()
    if not label:
        return "an unknown date"

    try:
        parsed = datetime.fromisoformat(label.replace("Z", "+00:00"))
    except ValueError:
        return label

    return parsed.strftime("%b %d, %Y")


def format_summary_html(summary: dict, mode: str = "", host_os: str = "") -> str:
    counts = summary.get("counts", {})
    limitations = summary.get("limitations", [])
    plain_summary = summary.get("plain_summary", [])
    guidance = build_visibility_guidance(limitations, host_os)
    friendly_limitations = guidance.get("friendly_notes", [])

    summary_lines = "".join(
        f"<li>{line}</li>" for line in plain_summary
    ) or "<li>AuditOS is still gathering enough context to describe this scan.</li>"

    limitation_block = ""
    if friendly_limitations:
        limitation_items = "".join(f"<li>{note}</li>" for note in friendly_limitations)
        summary_hint = guidance.get("summary_hint") or ""
        if summary_hint:
            limitation_items += f"<li>{summary_hint}</li>"
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
    <div style="color: #202124; line-height: 1.45;">
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
        self.current_background_tasks = []
        self.previous_report = None

        self.thread = None
        self.worker = None
        self.audit_running = False
        self.current_audit_origin = None
        self.last_limitations_signature = ""
        self.schedule_timer = QTimer(self)
        self.schedule_timer.setSingleShot(True)
        self.schedule_timer.timeout.connect(self.handle_schedule_timer)

        self.status = QLabel("AuditOS - System Transparency Audit Tool")
        self.schedule_status = QLabel()
        self.schedule_status.setStyleSheet("color: #5f6368; padding: 2px 2px 8px 2px;")
        self.schedule_status.setWordWrap(True)
        self.scorecard_title = QLabel("AuditOS Scorecard")
        self.scorecard_risk = QLabel("Overall Risk: UNKNOWN")
        self.scorecard_title.setStyleSheet("font-size: 28px; font-weight: 800; color: #202124;")
        self.scorecard_risk.setStyleSheet("font-size: 22px; font-weight: 800; color: #444444;")

        self.quick = QPushButton("Quick Audit")
        self.deep = QPushButton("Deep Audit")
        self.baseline = QPushButton("Save Baseline")
        self.settings_btn = QPushButton("Settings")
        self.update_btn = QPushButton("Check for Updates")
        self.export_btn = QPushButton("Export Report")

        self.quick.clicked.connect(lambda: self.run_audit("quick"))
        self.deep.clicked.connect(lambda: self.run_audit("deep"))
        self.baseline.clicked.connect(self.save_current_baseline)
        self.settings_btn.clicked.connect(self.open_settings)
        self.update_btn.clicked.connect(self.check_for_updates)
        self.export_btn.clicked.connect(self.export_report)

        button_row = QHBoxLayout()
        for b in [self.quick, self.deep, self.baseline, self.settings_btn, self.update_btn, self.export_btn]:
            button_row.addWidget(b)

        self.findings = FindingsTable()
        self.changes_table = ChangesTable()
        self.behavior_table = BehaviorTable()
        self.background_tasks_table = BackgroundTasksTable()

        self.details = QTextEdit()
        self.details.setReadOnly(True)
        self.details.setMinimumHeight(250)
        self.behavior_detail = QLabel("Select a behavior item to read the full explanation.")
        self.behavior_detail.setWordWrap(True)
        self.behavior_detail.setTextFormat(Qt.PlainText)
        self.behavior_detail.setStyleSheet("color: #5f6368; padding: 8px 4px;")
        self.background_task_detail = QTextEdit()
        self.background_task_detail.setReadOnly(True)
        self.background_task_detail.setMinimumHeight(210)
        self.background_task_detail.setPlainText(
            "Run Deep Audit, then select a background task to read what AuditOS thinks it is doing, what launched it, and what ending it might affect."
        )
        self.background_task_detail.setStyleSheet("color: #5f6368; padding: 8px 4px;")
        self.background_tasks_splitter = QSplitter(Qt.Vertical)
        self.background_tasks_splitter.setChildrenCollapsible(False)
        self.background_tasks_splitter.addWidget(self.background_tasks_table)
        self.background_tasks_splitter.addWidget(self.background_task_detail)
        self.background_tasks_splitter.setStretchFactor(0, 3)
        self.background_tasks_splitter.setStretchFactor(1, 2)
        self.background_tasks_splitter.setSizes([360, 260])

        scorecard_header = QHBoxLayout()
        scorecard_header.addWidget(self.scorecard_title)
        scorecard_header.addStretch(1)
        scorecard_header.addWidget(self.scorecard_risk)

        self.changes_info_label = QLabel(
            "Changes compares this scan to your saved baseline or previous scan and explains why each new difference could matter."
        )
        self.changes_state_label = QLabel(
            "Run a scan, then AuditOS will compare it to your saved baseline or previous scan here."
        )
        self.behavior_info_label = QLabel(
            "Behavior highlights live network activity, open ports, startup items, scheduled tasks, and extensions in plainer language so you can tell what each item is likely doing."
        )
        self.background_tasks_info_label = QLabel(
            "Background Tasks lists running processes from Deep Audit and translates them into plainer language so unfamiliar names are easier to reason about."
        )
        self.background_tasks_state_label = QLabel(
            "Run Deep Audit to inspect live background tasks and see which ones AuditOS thinks deserve a closer look."
        )
        for label in [
            self.changes_info_label,
            self.behavior_info_label,
            self.changes_state_label,
            self.background_tasks_info_label,
            self.background_tasks_state_label,
        ]:
            label.setWordWrap(True)
            label.setVisible(False)
            label.setStyleSheet("color: #5f6368; padding: 6px 8px;")
        self.changes_info_label.setVisible(True)
        self.changes_state_label.setVisible(True)
        self.background_tasks_info_label.setVisible(True)
        self.background_tasks_state_label.setVisible(True)

        self.changes_info_btn = self._make_info_button(self.changes_info_label)
        self.behavior_info_btn = self._make_info_button(self.behavior_info_label)
        self.background_tasks_info_btn = self._make_info_button(self.background_tasks_info_label)

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

        tab4 = QWidget()
        l4 = QVBoxLayout(tab4)
        l4.addLayout(self._build_info_row("About Background Tasks", self.background_tasks_info_btn))
        l4.addWidget(self.background_tasks_info_label)
        l4.addWidget(self.background_tasks_state_label)
        l4.addWidget(self.background_tasks_splitter, 1)

        self.tabs.addTab(tab1, "Findings")
        self.tabs.addTab(tab2, "Changes")
        self.tabs.addTab(tab3, "Behavior")
        self.tabs.addTab(tab4, "Background Tasks")

        layout = QVBoxLayout()
        layout.addWidget(self.status)
        layout.addLayout(button_row)
        layout.addWidget(self.schedule_status)
        layout.addWidget(self.tabs)

        container = QWidget()
        container.setLayout(layout)
        self.setCentralWidget(container)

        self.findings.itemSelectionChanged.connect(self.on_finding_selected)
        self.behavior_table.itemSelectionChanged.connect(self.on_behavior_selected)
        self.background_tasks_table.itemSelectionChanged.connect(self.on_background_task_selected)
        self.changes_table.load_changes([])
        self.refresh_background_tasks_view()
        self.refresh_changes_preview()
        self.configure_schedule()

        QTimer.singleShot(0, lambda: show_first_run_notice(self))

    def run_audit(self, mode, origin: str = "manual"):
        if self.audit_running:
            QMessageBox.information(self, "Audit Running", "Wait for the current scan to finish.")
            return

        log_message(f"UI requested audit mode={mode}")

        self.current_audit_origin = origin
        self.audit_running = True
        if origin == "scheduled":
            self.refresh_schedule_status()
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
        self.configure_schedule()
        self.current_audit_origin = None

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

            if self.current_audit_origin == "scheduled":
                # Advance the schedule as soon as the worker succeeds so a later
                # UI-only exception does not immediately retrigger the same run.
                self.complete_scheduled_audit()

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
            guidance = build_visibility_guidance(limitations, str(report.get("host_os", "")))
            overall_risk = str(summary.get("overall_risk", "unknown")).upper()

            status_text = f"Risk: {overall_risk}"
            if limitations:
                status_note = str(guidance.get("status_note", "")).strip()
                if status_note:
                    status_text += f" | {status_note}"
                else:
                    status_text += " | Limited visibility"

            self.status.setText(status_text)
            self.scorecard_risk.setText(f"Overall Risk: {overall_risk}")
            self.scorecard_risk.setStyleSheet(
                f"font-size: 22px; font-weight: 800; color: {_risk_color(overall_risk)};"
            )
            self.findings.load_findings(self.current_findings)
            self.behavior_table.load_behavior(self.current_behavior)
            self.refresh_background_tasks_view(report)
            mode = str(report.get("meta", {}).get("mode", ""))
            self.details.setHtml(format_summary_html(summary, mode, str(report.get("host_os", ""))))
            self.maybe_explain_limitations(limitations)
            self.refresh_changes_preview()

            self.maybe_prompt_for_baseline()

            log_message("UI update completed")

        except Exception:
            import traceback
            tb = traceback.format_exc()
            log_message(f"audit_finished crashed:\n{tb}")
            QMessageBox.critical(self, "Crash", tb)

    def audit_failed(self, message):
        log_message(f"audit_failed: {message}")
        if self.current_audit_origin == "scheduled":
            self.delay_scheduled_audit(60 * 60 * 1000, "Scheduled scan failed; retrying in 60 minutes")
        QMessageBox.critical(self, "Audit failed", message)

    def maybe_explain_limitations(self, limitations):
        if not limitations:
            self.last_limitations_signature = ""
            return

        signature = "\n".join(limitations)
        if signature == self.last_limitations_signature:
            return

        self.last_limitations_signature = signature
        host_os = ""
        if isinstance(self.current_report, dict):
            host_os = str(self.current_report.get("host_os", ""))
        guidance = build_visibility_guidance(limitations, host_os)

        box = QMessageBox(self)
        box.setWindowTitle(str(guidance.get("dialog_title", "Limited Audit Visibility")))
        box.setText(str(guidance.get("dialog_body", "")))

        friendly_notes = guidance.get("friendly_notes", [])
        if friendly_notes:
            note_text = "\n".join(f"• {note}" for note in friendly_notes)
            box.setInformativeText(note_text)

        primary_label = str(guidance.get("primary_button", "")).strip()
        primary_button = None
        if primary_label:
            primary_button = box.addButton(primary_label, QMessageBox.AcceptRole)
        keep_button = box.addButton(str(guidance.get("secondary_button", "Keep Limited Scan")), QMessageBox.RejectRole)
        box.exec()

        if primary_button and box.clickedButton() == primary_button:
            settings_url = str(guidance.get("settings_url", "")).strip()
            help_url = str(guidance.get("help_url", "")).strip()
            opened = False
            if settings_url:
                opened = QDesktopServices.openUrl(QUrl(settings_url))
            if not opened and help_url:
                QDesktopServices.openUrl(QUrl(help_url))
        elif box.clickedButton() == keep_button:
            log_message("User kept limited scan visibility")

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

    def on_background_task_selected(self):
        row = self.background_tasks_table.currentRow()
        task = self.background_tasks_table.task_at_row(row)
        if not task:
            self.background_task_detail.setPlainText(
                "Select a background task to read what AuditOS thinks it is doing, why it may be running, what launched it, and what ending it might affect."
            )
            return
        self.background_task_detail.setPlainText(self.format_background_task_detail(task))

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
                "No comparison source is available yet. Save a baseline or run another scan so AuditOS can explain what is newly different."
            )
            self.changes_state_label.setVisible(True)
            self.changes_table.load_changes([])
            return

        diff = build_diff(comparison_report, self.current_report)
        self.changes_table.load_changes(diff["changes"])
        if diff["count"] == 0:
            self.changes_info_label.setText(
                f"AuditOS compared this scan with your {comparison_label} and did not find any new differences that deserve explanation here."
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
            default_report_filename(self.current_report),
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

    def check_for_updates(self):
        self.status.setText(f"Checking for updates for AuditOS {APP_VERSION}...")
        QApplication.setOverrideCursor(Qt.WaitCursor)
        try:
            result = perform_update_check(APP_VERSION)
        except UpdateCheckError as exc:
            log_message(f"Update check failed: {exc}")
            self.status.setText("Could not check for updates")
            QMessageBox.warning(
                self,
                "Update Check Failed",
                f"{exc}\n\nYou can still review builds manually on GitHub Releases.",
            )
            return
        except Exception as exc:
            log_message(f"Unexpected update check error: {exc}")
            self.status.setText("Could not check for updates")
            QMessageBox.warning(
                self,
                "Update Check Failed",
                "AuditOS hit an unexpected problem while checking GitHub Releases.\n\n"
                "You can still review builds manually on GitHub Releases.",
            )
            return
        finally:
            QApplication.restoreOverrideCursor()

        self.handle_update_check_result(result)

    def handle_update_check_result(self, result: UpdateCheckResult):
        self.status.setText(result.message)

        if result.status == "update_available" and result.release:
            box = QMessageBox(self)
            box.setIcon(QMessageBox.Information)
            box.setWindowTitle("Update Available")
            box.setText(result.message)

            published_at = _format_release_date(result.release.published_at)
            channel_label = "beta build" if result.release.is_prerelease else "release"
            box.setInformativeText(
                f"Current version: {result.current_version}\n"
                f"Latest {channel_label}: {result.release.version}\n"
                f"Published: {published_at}\n\n"
                "Open the release page to download the newer build."
            )
            open_button = box.addButton("Open Release Page", QMessageBox.AcceptRole)
            box.addButton("Not Now", QMessageBox.RejectRole)
            box.exec()

            if box.clickedButton() == open_button:
                QDesktopServices.openUrl(QUrl(result.release.html_url or RELEASES_PAGE_URL))
            return

        if result.status == "up_to_date":
            QMessageBox.information(self, "Up to Date", result.message)
            return

        QMessageBox.information(self, "No Release Found", result.message)

    def open_settings(self):
        dialog = SettingsDialog(self)
        if dialog.exec():
            self.configure_schedule()

    def refresh_background_tasks_view(self, report=None):
        report = report or self.current_report or {}
        meta = report.get("meta", {}) if isinstance(report, dict) else {}
        mode = str(meta.get("mode", "")).lower()
        background_section = report.get("background_tasks", {}) if isinstance(report, dict) else {}
        items = background_section.get("items", []) if isinstance(background_section, dict) else []
        if not isinstance(items, list):
            items = []

        self.current_background_tasks = items

        if mode != "deep":
            self.background_tasks_state_label.setText(
                "Run Deep Audit to inspect live background tasks and see which ones AuditOS thinks deserve a closer look."
            )
            self.background_tasks_state_label.setVisible(True)
            self.background_tasks_table.load_tasks(
                [],
                "Deep Audit adds the live background-task view. Quick Audit does not collect running process details.",
            )
            self.background_task_detail.setPlainText(
                "Run Deep Audit, then select a background task to read what AuditOS thinks it is doing, what launched it, and what ending it might affect."
            )
            return

        review_count = sum(1 for item in items if str(item.get("review_status", "")) == "review")
        unknown_count = sum(1 for item in items if str(item.get("review_status", "")) == "unknown")
        auditos_count = sum(1 for item in items if str(item.get("role", "")) in {"auditos_app", "auditos_helper"})
        if items:
            summary = f"Showing {len(items)} background task(s) from this Deep Audit."
            if review_count:
                summary += f" {review_count} item(s) appear to deserve review first."
            elif unknown_count:
                summary += f" {unknown_count} item(s) are not yet confidently classified."
            else:
                summary += " AuditOS did not see any immediately suspicious patterns in the live task list."
            if auditos_count:
                summary += f" {auditos_count} AuditOS-related process(es) were recognized separately."
            self.background_tasks_state_label.setText(summary)
        else:
            self.background_tasks_state_label.setText(
                "Deep Audit did not return any background task details for this scan."
            )
        self.background_tasks_state_label.setVisible(True)
        self.background_tasks_table.load_tasks(
            items,
            "Deep Audit did not return any background task details for this scan.",
        )
        if items:
            self.background_tasks_table.selectRow(0)
            self.on_background_task_selected()
            self.background_tasks_splitter.setSizes([360, 260])
        else:
            self.background_task_detail.setPlainText(
                "Select a background task to read what AuditOS thinks it is doing, why it may be running, what launched it, and what ending it might affect."
            )

    def format_background_task_detail(self, task: dict) -> str:
        name = str(task.get("friendly_name") or task.get("name") or f"PID {task.get('pid', '?')}")
        raw_name = str(task.get("name", "")).strip()
        role_label = str(task.get("role_label", "Background task")).strip()
        review_label = str(task.get("review_label", "")).strip()
        review_reason = str(task.get("review_reason", "")).strip()
        explanation = str(task.get("explanation", "")).strip()
        command_summary = str(task.get("command_summary", "")).strip()
        launch_summary = str(task.get("launch_summary", "")).strip()
        impact_hint = str(task.get("impact_hint", "")).strip()
        exe = str(task.get("exe", "")).strip()
        cmdline_preview = str(task.get("cmdline_preview", "")).strip()
        parent_name = str(task.get("parent_friendly_name") or task.get("parent_name") or "").strip()
        parent_exe = str(task.get("parent_exe", "")).strip()
        parent_cmdline_preview = str(task.get("parent_cmdline_preview", "")).strip()
        ppid = task.get("ppid", "")
        status = str(task.get("status", "")).strip()
        username = str(task.get("username", "")).strip()
        pid = task.get("pid", "")

        parts = [
            name,
            f"AuditOS reads this as: {role_label}",
            f"Attention: {review_label or 'Likely normal'}",
            f"What it is probably doing: {explanation or 'No explanation available yet.'}",
        ]

        if command_summary:
            parts.append(f"What the command suggests: {command_summary}")
        if launch_summary:
            parts.append(f"Launch context: {launch_summary}")
        if review_reason:
            parts.append(f"Why AuditOS highlighted it: {review_reason}")
        if impact_hint:
            parts.append(f"Possible impact if ended: {impact_hint}")
        if parent_name:
            parent_line = f"Likely parent: {parent_name}"
            if isinstance(ppid, int):
                parent_line += f" (PID {ppid})"
            parts.append(parent_line)
        if parent_exe:
            parts.append(f"Parent path: {parent_exe}")
        if parent_cmdline_preview:
            parts.append(f"Parent command preview: {parent_cmdline_preview}")
        if raw_name and raw_name != name:
            parts.append(f"Raw process name: {raw_name}")
        if pid != "":
            parts.append(f"PID: {pid}")
        if status:
            parts.append(f"Status: {status}")
        if username:
            parts.append(f"User: {username}")
        if exe:
            parts.append(f"Path: {exe}")
        if cmdline_preview:
            parts.append(f"Command preview: {cmdline_preview}")

        return "\n\n".join(parts)

    def refresh_schedule_status(self, settings=None):
        settings = settings or load_settings()
        if not settings.get("schedule_enabled"):
            self.schedule_status.setText(
                "Automatic scans are off. Open Settings if you want AuditOS to rerun scans while AuditOS stays open."
            )
            return

        mode = str(settings.get("schedule_mode", "quick")).capitalize()
        frequency = str(settings.get("schedule_frequency", "weekly")).capitalize()

        if self.audit_running and self.current_audit_origin == "scheduled":
            self.schedule_status.setText(
                f"Automatic {mode.lower()} scan in progress. AuditOS will schedule the next {frequency.lower()} run when this one finishes."
            )
            return

        next_run_at = parse_schedule_timestamp(settings.get("schedule_next_run_at"))
        if not next_run_at:
            self.schedule_status.setText(
                f"Automatic scans are on, but the next {frequency.lower()} {mode.lower()} run has not been set yet. Reopen Settings to finish the schedule."
            )
            return

        local_time = next_run_at.astimezone()
        date_text = local_time.strftime("%b %d, %Y")
        time_text = local_time.strftime("%I:%M %p").lstrip("0")
        status_text = (
            f"Automatic scans are on. Next {mode.lower()} scan: {date_text} at {time_text} ({frequency.lower()})."
        )

        last_run_at = parse_schedule_timestamp(settings.get("schedule_last_run_at"))
        if last_run_at:
            last_local = last_run_at.astimezone()
            last_date_text = last_local.strftime("%b %d, %Y")
            last_time_text = last_local.strftime("%I:%M %p").lstrip("0")
            status_text += f" Last automatic scan: {last_date_text} at {last_time_text}."

        self.schedule_status.setText(status_text)

    def configure_schedule(self):
        settings = load_settings()
        if not settings.get("schedule_enabled"):
            self.schedule_timer.stop()
            self.refresh_schedule_status(settings)
            return

        updated = ensure_schedule_next_run(settings)
        if updated != settings:
            save_settings(updated)
            settings = updated

        interval_ms = next_schedule_timer_ms(settings)
        if interval_ms is None:
            self.schedule_timer.stop()
            self.refresh_schedule_status(settings)
            return

        frequency = str(settings.get("schedule_frequency", "weekly")).lower()
        next_run_at = settings.get("schedule_next_run_at", "unknown")
        self.schedule_timer.start(interval_ms)
        self.refresh_schedule_status(settings)
        log_message(
            f"Scheduled scans armed: mode={settings.get('schedule_mode', 'quick')} frequency={frequency} next_run_at={next_run_at}"
        )

    def handle_schedule_timer(self):
        settings = load_settings()
        if not settings.get("schedule_enabled"):
            return

        if not is_schedule_due(settings):
            interval_ms = next_schedule_timer_ms(settings)
            if interval_ms is not None:
                self.schedule_timer.start(interval_ms)
            return

        self.run_scheduled_audit()

    def complete_scheduled_audit(self):
        settings = load_settings()
        updated = mark_schedule_completed(settings)
        save_settings(updated)
        self.refresh_schedule_status(updated)
        log_message(f"Scheduled scan completed; next_run_at={updated.get('schedule_next_run_at')}")

    def delay_scheduled_audit(self, delay_ms: int, reason: str):
        settings = load_settings()
        updated = delay_schedule_until(settings, delay_ms)
        save_settings(updated)
        self.configure_schedule()
        log_message(f"{reason} next_run_at={updated.get('schedule_next_run_at')}")

    def run_scheduled_audit(self):
        settings = load_settings()
        if self.audit_running:
            self.delay_scheduled_audit(15 * 60 * 1000, "Scheduled scan delayed because another audit is running")
            return

        mode = str(settings.get("schedule_mode", "quick")).lower()
        log_message(f"Starting scheduled audit mode={mode}")
        self.run_audit(mode, origin="scheduled")
