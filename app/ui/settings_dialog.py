from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QLabel,
)

from services.baseline_store import load_settings, save_settings
from services.schedule_state import parse_schedule_timestamp


class SettingsDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Settings")

        self.settings = load_settings()

        self.schedule = QCheckBox("Run scans automatically while AuditOS is open")
        self.schedule.setChecked(self.settings.get("schedule_enabled", False))

        self.frequency = QComboBox()
        self.frequency.addItems(["daily", "weekly", "monthly"])
        self.frequency.setCurrentText(self.settings.get("schedule_frequency", "weekly"))

        self.mode = QComboBox()
        self.mode.addItems(["quick", "deep"])
        self.mode.setCurrentText(self.settings.get("schedule_mode", "quick"))

        self.ai = QCheckBox()
        self.ai.setChecked(self.settings["ai_enabled"])

        self.schedule_preview = QLabel()
        self.schedule_preview.setWordWrap(True)
        self.schedule_preview.setStyleSheet("color: #5f6368; padding-top: 2px;")

        form = QFormLayout(self)
        form.addRow(self.schedule)
        form.addRow("Schedule frequency", self.frequency)
        form.addRow("Scheduled scan type", self.mode)

        note = QLabel(
            "Automatic scans are a beta convenience feature. AuditOS only runs them while the app is open."
        )
        note.setWordWrap(True)
        form.addRow(note)
        form.addRow(self.schedule_preview)
        form.addRow("Enable AI explanations (coming soon)", self.ai)

        self.schedule.toggled.connect(self.update_schedule_controls)
        self.frequency.currentTextChanged.connect(self.update_schedule_controls)
        self.mode.currentTextChanged.connect(self.update_schedule_controls)
        self.update_schedule_controls()

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.save)
        buttons.rejected.connect(self.reject)
        form.addRow(buttons)

    def save(self):
        updated = dict(self.settings)
        previous_enabled = bool(self.settings.get("schedule_enabled"))
        previous_frequency = str(self.settings.get("schedule_frequency", "weekly")).lower()
        next_enabled = self.schedule.isChecked()
        next_frequency = self.frequency.currentText()

        updated.update(
            {
                "schedule_enabled": next_enabled,
                "schedule_frequency": next_frequency,
                "schedule_mode": self.mode.currentText(),
                "ai_enabled": self.ai.isChecked(),
                "license_tier": "free",
            }
        )

        if not next_enabled:
            updated["schedule_next_run_at"] = None
        elif not previous_enabled or previous_frequency != next_frequency.lower():
            updated["schedule_next_run_at"] = None

        save_settings(updated)
        self.accept()

    def update_schedule_controls(self):
        enabled = self.schedule.isChecked()
        self.frequency.setEnabled(enabled)
        self.mode.setEnabled(enabled)
        self.schedule_preview.setText(self.build_schedule_preview())

    def build_schedule_preview(self) -> str:
        if not self.schedule.isChecked():
            return (
                "Automatic scans are currently off. Turn this on if you want AuditOS to rerun scans for you while AuditOS stays open."
            )

        frequency = self.frequency.currentText().lower()
        mode = self.mode.currentText().capitalize()

        previous_enabled = bool(self.settings.get("schedule_enabled"))
        previous_frequency = str(self.settings.get("schedule_frequency", "weekly")).lower()
        next_run_at = parse_schedule_timestamp(self.settings.get("schedule_next_run_at"))
        next_run_will_reset = (
            not previous_enabled
            or previous_frequency != frequency
            or next_run_at is None
        )

        if next_run_will_reset:
            return (
                f"AuditOS will run a {mode.lower()} scan every {frequency} while the app is open. "
                "The first automatic run time for this schedule will be set when you save."
            )

        local_time = next_run_at.astimezone()
        date_text = local_time.strftime("%b %d, %Y")
        time_text = local_time.strftime("%I:%M %p").lstrip("0")
        return (
            f"AuditOS will keep running a {mode.lower()} scan every {frequency} while the app is open. "
            f"Next automatic scan: {date_text} at {time_text}."
        )
