from PySide6.QtWidgets import (
    QDialog,
    QCheckBox,
    QComboBox,
    QFormLayout,
    QDialogButtonBox
)

from services.baseline_store import load_settings, save_settings


class SettingsDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Settings")

        settings = load_settings()

        self.schedule = QCheckBox()
        self.schedule.setChecked(settings["schedule_enabled"])

        self.frequency = QComboBox()
        self.frequency.addItems(["daily", "weekly", "monthly"])
        self.frequency.setCurrentText(settings["schedule_frequency"])

        self.ai = QCheckBox()
        self.ai.setChecked(settings["ai_enabled"])

        form = QFormLayout(self)
        form.addRow("Enable scheduled audits", self.schedule)
        form.addRow("Schedule frequency", self.frequency)
        form.addRow("Enable AI explanations", self.ai)

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.save)
        buttons.rejected.connect(self.reject)
        form.addRow(buttons)

    def save(self):
        save_settings({
            "schedule_enabled": self.schedule.isChecked(),
            "schedule_frequency": self.frequency.currentText(),
            "schedule_mode": "quick",
            "ai_enabled": self.ai.isChecked(),
            "license_tier": "free",
        })
        self.accept()
