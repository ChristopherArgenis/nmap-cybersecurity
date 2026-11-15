"""Pantalla «Cambios»: qué cambió en la red entre dos escaneos."""

from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QComboBox,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

from nmap_gui.core.history import ScanRecord

from ..core.changes import ChangeSet
from ..theme import THEMES
from ..widgets import Card, StatCard
from .scan_page import page_header

_SEVERITY_COLOR = {"alto": "danger", "medio": "warn", "bajo": "info", "info": "accent"}
_SEVERITY_TEXT = {"alto": "Revisar ya", "medio": "Revisar", "bajo": "Para saber", "info": "Bien / neutro"}


class ChangesPage(QWidget):
    compare_requested = Signal(int, int)  # id del escaneo anterior, id del posterior
    demo_requested = Signal()

    def __init__(self, theme: str, parent: QWidget | None = None):
        super().__init__(parent)
        self.setObjectName("Root")
        self.theme = theme
        self.changes = ChangeSet()

        lay = QVBoxLayout(self)
        lay.setContentsMargins(28, 24, 28, 24)
        lay.setSpacing(16)
        lay.addWidget(page_header(
            "Vigilancia de cambios",
            "Compara dos escaneos de la misma red: equipos nuevos, puertos que se abren o se cierran."))

        pick = Card(shadow=False)
        row = QHBoxLayout()
        row.setSpacing(10)
        self.before = QComboBox()
        self.after = QComboBox()
        for combo, name in ((self.before, "Escaneo anterior"), (self.after, "Escaneo posterior")):
            combo.setMinimumWidth(260)
            combo.setAccessibleName(name)
        lbl_a = QLabel("Antes")
        lbl_a.setObjectName("Muted")
        lbl_b = QLabel("Después")
        lbl_b.setObjectName("Muted")
        self.btn_compare = QPushButton("Comparar")
        self.btn_compare.setObjectName("AccentButton")
        row.addWidget(lbl_a)
        row.addWidget(self.before, 1)
        row.addWidget(lbl_b)
        row.addWidget(self.after, 1)
        row.addWidget(self.btn_compare)
        pick.body.addLayout(row)
        self.pick_hint = QLabel("Cada escaneo terminado se compara solo con el anterior de los mismos objetivos.")
        self.pick_hint.setObjectName("Muted")
        self.pick_hint.setWordWrap(True)
        pick.body.addWidget(self.pick_hint)
        lay.addWidget(pick)

        self.title = QLabel()
        self.title.setObjectName("CardTitle")
        self.title.setWordWrap(True)
        lay.addWidget(self.title)

        stats = QHBoxLayout()
        stats.setSpacing(14)
        self.stat_new = StatCard("Equipos nuevos")
        self.stat_open = StatCard("Puertos abiertos nuevos")
        self.stat_closed = StatCard("Puertos cerrados")
        self.stat_other = StatCard("Otros cambios")
        for s in (self.stat_new, self.stat_open, self.stat_closed, self.stat_other):
            stats.addWidget(s)
        lay.addLayout(stats)

        self.scroll = QScrollArea()
        self.scroll.setWidgetResizable(True)
        self.scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.list = QWidget()
        self.list.setObjectName("Root")
        self.list_layout = QVBoxLayout(self.list)
        self.list_layout.setContentsMargins(0, 0, 4, 0)
        self.list_layout.setSpacing(8)
        self.scroll.setWidget(self.list)
        lay.addWidget(self.scroll, 1)

        self.btn_compare.clicked.connect(self._request)
        self.set_changes(ChangeSet())

    # ------------------------------------------------------------ datos
    def set_history(self, records: list[ScanRecord]) -> None:
        """Llena los selectores con el historial (más reciente primero)."""
        for combo in (self.before, self.after):
            combo.blockSignals(True)
            combo.clear()
            for rec in records:
                combo.addItem(f"{rec.started_text} · {rec.targets} · {rec.hosts_up} equipos", rec.id)
            combo.blockSignals(False)
        if len(records) >= 2:
            self.after.setCurrentIndex(0)
            self.before.setCurrentIndex(1)
        self.btn_compare.setEnabled(len(records) >= 2)

    def _request(self) -> None:
        a, b = self.before.currentData(), self.after.currentData()
        if a is not None and b is not None and a != b:
            self.compare_requested.emit(a, b)

    def apply_theme(self, theme: str) -> None:
        self.theme = theme
        self.set_changes(self.changes)

    def set_changes(self, changes: ChangeSet) -> None:
        self.changes = changes
        c = THEMES[self.theme]
        while self.list_layout.count():
            item = self.list_layout.takeAt(0)
            w = item.widget()
            if w:
                w.hide()
                w.setParent(None)
                w.deleteLater()

        compared = bool(changes.before_label or changes.after_label)
        if compared:
            self.title.setText(f"{changes.before_label}  →  {changes.after_label}")
        else:
            self.title.setText("Aún no hay nada que comparar")
        n_other = len(changes.of_kind("servicio_cambiado")) + len(changes.of_kind("so_cambiado")) \
            + len(changes.of_kind("host_desaparecido"))
        self.stat_new.set_value(str(len(changes.of_kind("host_nuevo"))) if compared else "—")
        self.stat_open.set_value(str(len(changes.of_kind("puerto_abierto"))) if compared else "—")
        self.stat_closed.set_value(str(len(changes.of_kind("puerto_cerrado"))) if compared else "—")
        self.stat_other.set_value(str(n_other) if compared else "—")
        self.stat_new.set_accent(c["info"])
        self.stat_open.set_accent(c["warn"])
        self.stat_closed.set_accent(c["accent"])

        if not compared:
            msg = QLabel("Haz dos escaneos de la misma red (por ejemplo, uno hoy y otro la próxima semana) "
                         "y aquí verás qué cambió. También puedes probarlo con la red de ejemplo.")
            msg.setObjectName("Muted")
            msg.setWordWrap(True)
            demo = QPushButton("Ver red de ejemplo")
            demo.setObjectName("AccentButton")
            demo.clicked.connect(self.demo_requested)
            self.list_layout.addWidget(msg)
            self.list_layout.addWidget(demo, 0, Qt.AlignmentFlag.AlignLeft)
        elif changes.empty:
            ok = QLabel("Sin cambios: la red se ve igual que en el escaneo anterior.")
            ok.setObjectName("CardTitle")
            self.list_layout.addWidget(ok)
        else:
            for ch in changes.changes:
                color = c[_SEVERITY_COLOR[ch.severity]]
                box = QLabel(
                    f"<span style='color:{color}'><b>{_SEVERITY_TEXT[ch.severity]}</b></span> · "
                    f"<b>{ch.title}</b><br>{ch.detail}")
                box.setObjectName("Inset")
                box.setWordWrap(True)
                box.setContentsMargins(12, 10, 12, 10)
                box.setStyleSheet(f"#Inset {{ border-left: 3px solid {color}; }}")
                self.list_layout.addWidget(box)
        self.list_layout.addStretch(1)
