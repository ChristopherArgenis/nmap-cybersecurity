"""Pantalla «Ajustes»: tema, ruta de nmap y aviso de uso responsable."""

from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import QHBoxLayout, QLabel, QLineEdit, QPushButton, QVBoxLayout, QWidget

from ..widgets import Card, ToggleSwitch
from .scan_page import page_header


class SettingsPage(QWidget):
    theme_changed = Signal(str)
    browse_requested = Signal()
    nmap_path_changed = Signal(str)

    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent)
        self.setObjectName("Root")
        lay = QVBoxLayout(self)
        lay.setContentsMargins(28, 24, 28, 24)
        lay.setSpacing(16)
        lay.addWidget(page_header("Ajustes", "Personaliza la aplicación."))

        look = Card("Apariencia")
        self.dark = ToggleSwitch("Modo oscuro")
        look.body.addWidget(self.dark)
        lay.addWidget(look)

        nm = Card("nmap")
        self.nmap_status = QLabel()
        self.nmap_status.setObjectName("Muted")
        self.nmap_status.setWordWrap(True)
        row = QHBoxLayout()
        self.nmap_path = QLineEdit()
        self.nmap_path.setPlaceholderText("Detección automática")
        self.btn_browse = QPushButton("Buscar…")
        row.addWidget(self.nmap_path, 1)
        row.addWidget(self.btn_browse)
        nm.body.addWidget(self.nmap_status)
        nm.body.addLayout(row)
        hint = QLabel(
            "¿No tienes nmap? Descárgalo de <a href='https://nmap.org/download.html'>nmap.org/download</a>. "
            "En Windows el instalador incluye Npcap, necesario para escanear."
        )
        hint.setObjectName("Muted")
        hint.setOpenExternalLinks(True)
        hint.setWordWrap(True)
        nm.body.addWidget(hint)
        lay.addWidget(nm)

        legal = Card("Uso responsable")
        txt = QLabel(
            "Escanea solo redes y equipos propios o donde tengas permiso explícito. "
            "Escanear redes ajenas (escuela, trabajo, redes públicas) sin autorización puede ser ilegal."
        )
        txt.setWordWrap(True)
        txt.setObjectName("Muted")
        legal.body.addWidget(txt)
        lay.addWidget(legal)

        self.about = QLabel()
        self.about.setObjectName("Muted")
        self.about.setAlignment(Qt.AlignmentFlag.AlignLeft)
        lay.addWidget(self.about)
        lay.addStretch(1)

        self.dark.toggled.connect(lambda on: self.theme_changed.emit("oscuro" if on else "claro"))
        self.btn_browse.clicked.connect(self.browse_requested)
        self.nmap_path.editingFinished.connect(lambda: self.nmap_path_changed.emit(self.nmap_path.text().strip()))
