from PySide6.QtWidgets import (
    QDialog,
    QCheckBox,
    QComboBox,
    QLabel,
    QFormLayout,
    QDialogButtonBox
)

from services.baseline_store import load_settings, save_settings


class SettingsDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Settings")

        settings = load_settings()

        self.schedule = QCheckBox("Run scans automatically while AuditOS is open")
        self.schedule.setChecked(settings.get("schedule_enabled", False))

        self.frequency = QComboBox()
        self.frequency.addItems(["daily", "weekly", "monthly"])
        self.frequency.setCurrentText(settings.get("schedule_frequency", "weekly"))

        self.mode = QComboBox()
        self.mode.addItems(["quick", "deep"])
        self.mode.setCurrentText(settings.get("schedule_mode", "quick"))

        self.ai = QCheckBox()
        self.ai.setChecked(settings["ai_enabled"])

        form = QFormLayout(self)
        form.addRow(self.schedule)
        form.addRow("Schedule frequency", self.frequency)
        form.addRow("Scheduled scan type", self.mode)
        note = QLabel("Beta note: scheduled scans run automatically while AuditOS is open.")
        note.setWordWrap(True)
        form.addRow(note)
        form.addRow("Enable AI explanations (coming soon)", self.ai)
        self.schedule.toggled.connect(self.update_schedule_controls)
        self.update_schedule_controls()

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.save)
        buttons.rejected.connect(self.reject)
        form.addRow(buttons)

    def save(self):
        save_settings({
            "schedule_enabled": self.schedule.isChecked(),
            "schedule_frequency": self.frequency.currentText(),
            "schedule_mode": self.mode.currentText(),
            "ai_enabled": self.ai.isChecked(),
            "license_tier": "free",
        })
        self.accept()

    def update_schedule_controls(self):
        enabled = self.schedule.isChecked()
        self.frequency.setEnabled(enabled)
        self.mode.setEnabled(enabled)
