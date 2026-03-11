from PySide6.QtWidgets import QMessageBox

def show_first_run_notice(parent):

    msg=QMessageBox(parent)

    msg.setWindowTitle("AuditOS Notice")

    msg.setText(
        "AuditOS is a system audit and transparency tool.\n\n"
        "It is NOT antivirus software and does not guarantee system security.\n\n"
        "Its purpose is to help users understand what their system is doing."
    )

    msg.setStandardButtons(QMessageBox.Ok)
    msg.exec()
