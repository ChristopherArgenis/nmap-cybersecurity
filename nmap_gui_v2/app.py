"""Punto de entrada de NMAP Studio (versión 2)."""

from __future__ import annotations

import sys

from PySide6.QtGui import QFont
from PySide6.QtWidgets import QApplication

from .main_window import ModernWindow


def main() -> int:
    app = QApplication(sys.argv)
    app.setApplicationName("nmap-studio")
    app.setOrganizationName("nmap-cybersecurity")
    app.setStyle("Fusion")  # base neutra para que el estilo propio se vea igual en todos los sistemas
    font = QFont("Segoe UI" if sys.platform == "win32" else app.font().family())
    font.setPointSizeF(10)
    app.setFont(font)
    window = ModernWindow()
    if not window.show_disclaimer_once():
        return 0
    window.show()
    return app.exec()
