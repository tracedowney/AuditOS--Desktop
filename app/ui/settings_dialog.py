from PySide6.QtWidgets import (
    QDialog,
    QCheckBox,
    QFormLayout,
    QDialogButtonBox
)

from services.baseline_store import load_settings, save_settings


class SettingsDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Settings")

        settings = load_settings()

        self.ai = QCheckBox()
        self.ai.setChecked(settings["ai_enabled"])

        form = QFormLayout(self)
        form.addRow("Enable AI explanations (coming soon)", self.ai)

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.save)
        buttons.rejected.connect(self.reject)
        form.addRow(buttons)

    def save(self):
        save_settings({
            "ai_enabled": self.ai.isChecked(),
            "license_tier": "free",
        })
        self.accept()
