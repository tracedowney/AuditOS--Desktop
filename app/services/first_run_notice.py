from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from services.app_paths import ensure_user_data_dir
from version_info import APP_VERSION, DISCLOSURE_VERSION

from PySide6.QtWidgets import (
    QDialog,
    QVBoxLayout,
    QLabel,
    QTextEdit,
    QPushButton,
    QCheckBox,
    QHBoxLayout,
)

APP_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = ensure_user_data_dir()

ACK_FILE = DATA_DIR / "terms_acknowledged.json"
TERMS_FILE = APP_DIR.parent / "TERMS_OF_USE.txt"


MISSION = (
    "AuditOS helps you understand what your system is doing — "
    "so you can make informed decisions about it."
)

PRIVACY = (
    "All data collected during an audit stays on your machine.\n"
    "Your data remains your data — it never leaves your computer.\n"
    "AuditOS does not transmit system information anywhere."
)

EXTRA = (
    "AuditOS is an informational audit tool and does not automatically fix or remove system components.\n\n"
    "AuditOS performs audits only when you choose to run them.\n"
    "AuditOS does not run background monitoring on its own. If you enable scheduled scans later, they run only while AuditOS is open.\n\n"
    "Quick Audit is the faster default scan.\n"
    "Deep Audit adds more network visibility, but some platforms may limit what AuditOS can see unless the OS grants access."
)


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _load_ack_payload() -> dict | None:
    if not ACK_FILE.exists():
        return None
    try:
        return json.loads(ACK_FILE.read_text(encoding="utf-8"))
    except Exception:
        return None


def acknowledged() -> bool:
    payload = _load_ack_payload()
    if not isinstance(payload, dict):
        return False
    if payload.get("accepted") is not True:
        return False
    return payload.get("notice_version") == DISCLOSURE_VERSION


def save_ack():
    payload = {
        "accepted": True,
        "timestamp": _utc_now_iso(),
        "app_version": APP_VERSION,
        "notice_version": DISCLOSURE_VERSION,
    }
    ACK_FILE.write_text(json.dumps(payload, indent=2), encoding="utf-8")


class FirstRunDialog(QDialog):

    def __init__(self):
        super().__init__()

        self.setWindowTitle("Welcome to AuditOS")
        self.setMinimumWidth(500)

        layout = QVBoxLayout()

        header = QLabel("<h2>AuditOS</h2>")
        layout.addWidget(header)

        mission = QLabel(MISSION)
        mission.setWordWrap(True)
        layout.addWidget(mission)

        privacy = QLabel(PRIVACY)
        privacy.setWordWrap(True)
        layout.addWidget(privacy)

        extra = QLabel(EXTRA)
        extra.setWordWrap(True)
        layout.addWidget(extra)

        self.checkbox = QCheckBox("I understand how AuditOS works and agree to the Terms of Use")
        layout.addWidget(self.checkbox)

        buttons = QHBoxLayout()

        view_terms = QPushButton("View Terms")
        view_terms.clicked.connect(self.show_terms)

        self.continue_btn = QPushButton("Continue")
        self.continue_btn.setEnabled(False)
        self.continue_btn.clicked.connect(self.accept_terms)

        buttons.addWidget(view_terms)
        buttons.addWidget(self.continue_btn)

        layout.addLayout(buttons)

        self.checkbox.stateChanged.connect(self.update_button)

        self.setLayout(layout)

    def update_button(self):
        self.continue_btn.setEnabled(self.checkbox.isChecked())

    def show_terms(self):
        text = ""

        if TERMS_FILE.exists():
            text = TERMS_FILE.read_text(encoding="utf-8")
        else:
            text = "Terms file not found."

        dialog = QDialog(self)
        dialog.setWindowTitle("Terms of Use")

        v = QVBoxLayout()

        box = QTextEdit()
        box.setPlainText(text)
        box.setReadOnly(True)

        v.addWidget(box)

        close = QPushButton("Close")
        close.clicked.connect(dialog.close)

        v.addWidget(close)

        dialog.setLayout(v)
        dialog.resize(600, 400)
        dialog.exec()

    def accept_terms(self):
        save_ack()
        self.accept()


def show_first_run_notice(parent=None):
    if acknowledged():
        return

    dialog = FirstRunDialog()
    dialog.exec()
