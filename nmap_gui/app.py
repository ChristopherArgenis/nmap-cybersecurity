"""Punto de entrada de la aplicación."""

from __future__ import annotations

import sys

from PySide6.QtWidgets import QApplication

from .ui.main_window import MainWindow


def main() -> int:
    app = QApplication(sys.argv)
    app.setApplicationName("nmap-gui")
    app.setOrganizationName("nmap-cybersecurity")
    window = MainWindow()
    if not window.show_disclaimer_once():
        return 0
    window.show()
    return app.exec()
