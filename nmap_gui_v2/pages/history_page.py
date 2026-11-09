"""Pantalla «Historial»: escaneos anteriores guardados en SQLite."""

from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QAbstractItemView,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from nmap_gui.core.history import History

from ..widgets import Card
from .scan_page import page_header


class HistoryPage(QWidget):
    open_requested = Signal(int)
    rerun_requested = Signal(int)
    delete_requested = Signal(int)
    clear_requested = Signal()

    def __init__(self, history: History, parent: QWidget | None = None):
        super().__init__(parent)
        self.setObjectName("Root")
        self.history = history
        lay = QVBoxLayout(self)
        lay.setContentsMargins(28, 24, 28, 24)
        lay.setSpacing(16)

        head = QHBoxLayout()
        head.addWidget(page_header("Historial", "Cada escaneo se guarda automáticamente en este equipo."), 1)
        self.btn_clear = QPushButton("Vaciar historial")
        head.addWidget(self.btn_clear, 0, Qt.AlignmentFlag.AlignBottom)
        lay.addLayout(head)

        card = Card()
        self.table = QTableWidget(0, 6)
        self.table.setHorizontalHeaderLabels(["Fecha", "Objetivos", "Hosts", "Abiertos", "Duración", "Comando"])
        self.table.verticalHeader().setVisible(False)
        self.table.setShowGrid(False)
        self.table.verticalHeader().setDefaultSectionSize(40)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        hdr = self.table.horizontalHeader()
        hdr.setSectionResizeMode(5, QHeaderView.ResizeMode.Stretch)
        hdr.setDefaultAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
        card.body.addWidget(self.table, 1)

        actions = QHBoxLayout()
        self.btn_open = QPushButton("Ver resultados")
        self.btn_open.setObjectName("AccentButton")
        self.btn_rerun = QPushButton("Repetir escaneo")
        self.btn_delete = QPushButton("Eliminar")
        for b in (self.btn_open, self.btn_rerun, self.btn_delete):
            actions.addWidget(b)
        actions.addStretch(1)
        self.count = QLabel()
        self.count.setObjectName("Muted")
        actions.addWidget(self.count)
        card.body.addLayout(actions)
        lay.addWidget(card, 1)

        self.table.doubleClicked.connect(lambda _: self._emit(self.open_requested))
        self.table.itemSelectionChanged.connect(self._sync_buttons)
        self.btn_open.clicked.connect(lambda: self._emit(self.open_requested))
        self.btn_rerun.clicked.connect(lambda: self._emit(self.rerun_requested))
        self.btn_delete.clicked.connect(lambda: self._emit(self.delete_requested))
        self.btn_clear.clicked.connect(self.clear_requested)
        self.reload()

    def reload(self) -> None:
        records = self.history.list()
        self.table.setRowCount(len(records))
        for row, rec in enumerate(records):
            duration = f"{rec.duration:.1f} s" if rec.duration is not None else "—"
            values = [rec.started_text, rec.targets, str(rec.hosts_up), str(rec.open_ports), duration, rec.command]
            for col, val in enumerate(values):
                item = QTableWidgetItem(val)
                item.setData(Qt.ItemDataRole.UserRole, rec.id)
                self.table.setItem(row, col, item)
        self.table.resizeColumnsToContents()
        self.table.horizontalHeader().setSectionResizeMode(5, QHeaderView.ResizeMode.Stretch)
        self.count.setText(f"{len(records)} escaneo(s) guardado(s)")
        self._sync_buttons()

    def _selected_id(self) -> int | None:
        items = self.table.selectedItems()
        return items[0].data(Qt.ItemDataRole.UserRole) if items else None

    def _sync_buttons(self) -> None:
        has = self._selected_id() is not None
        for b in (self.btn_open, self.btn_rerun, self.btn_delete):
            b.setEnabled(has)

    def _emit(self, signal) -> None:
        scan_id = self._selected_id()
        if scan_id is not None:
            signal.emit(scan_id)
