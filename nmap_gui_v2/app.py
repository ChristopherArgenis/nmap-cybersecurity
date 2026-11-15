"""Punto de entrada de NMAP Studio (versión 2)."""

from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path


def self_test() -> int:
    """Arranca la app sin ventana, carga la red de ejemplo y sale.

    La usa la compilación para comprobar que el .exe abre en Windows.
    No ejecuta nmap ni toca la red. Devuelve 0 si todo funciona.
    """
    os.environ["QT_QPA_PLATFORM"] = "offscreen"
    from PySide6.QtCore import QSettings
    from PySide6.QtWidgets import QApplication

    from .main_window import ModernWindow

    app = QApplication.instance() or QApplication([sys.argv[0]])
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
        settings = QSettings(str(Path(tmp) / "s.ini"), QSettings.Format.IniFormat)
        window = ModernWindow(history_path=Path(tmp) / "h.db", settings=settings)
        window.load_demo()
        app.processEvents()
        ok = len(window.topology_page.items) > 0 and len(window.osi_page.cards) == 7
        window.close()
        window.history.close()  # en Windows, para poder borrar la carpeta temporal
    return 0 if ok else 1


def main() -> int:
    if "--self-test" in sys.argv:
        return self_test()

    from PySide6.QtGui import QFont
    from PySide6.QtWidgets import QApplication

    from .main_window import ModernWindow

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
