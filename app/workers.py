from __future__ import annotations
import traceback
from PySide6.QtCore import QObject, QThread, Signal, Slot
from engine_adapter import run_audit
from services.crash_logger import log_message

class AuditWorker(QObject):
    finished = Signal(dict)
    failed = Signal(str)
    progress = Signal(str)

    def __init__(self, mode: str):
        super().__init__()
        self.mode = mode

    @Slot()
    def run(self):
        try:
            log_message(f"Worker starting audit mode={self.mode}")
            self.progress.emit(f"Starting {self.mode} audit...")

            report = run_audit(mode=self.mode)

            self.progress.emit("Audit complete")
            log_message(f"Worker finished audit mode={self.mode}")
            self.finished.emit(report)

        except Exception as exc:
            tb = traceback.format_exc()
            log_message(f"Worker exception: {tb}")
            self.failed.emit(tb)

def start_audit_in_thread(mode: str):
    thread = QThread()
    worker = AuditWorker(mode)
    worker.moveToThread(thread)
    thread.started.connect(worker.run)
    return thread, worker
