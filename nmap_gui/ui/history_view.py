"""Tabla con el historial de escaneos guardados."""

from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QAbstractItemView,
    QHBoxLayout,
    QHeaderView,
    QMessageBox,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from ..core.history import History


class HistoryView(QWidget):
    open_requested = Signal(int)
    rerun_requested = Signal(int)

    def __init__(self, history: History, parent: QWidget | None = None):
        super().__init__(parent)
        self.history = history

        self.table = QTableWidget(0, 6)
        self.table.setHorizontalHeaderLabels(["Fecha", "Objetivos", "Hosts", "Abiertos", "Duración", "Comando"])
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.verticalHeader().setVisible(False)
        self.table.horizontalHeader().setSectionResizeMode(5, QHeaderView.ResizeMode.Stretch)
        self.table.doubleClicked.connect(lambda _: self._emit(self.open_requested))

        buttons = QHBoxLayout()
        self.btn_open = QPushButton("Abrir")
        self.btn_rerun = QPushButton("Repetir escaneo")
        self.btn_delete = QPushButton("Eliminar")
        self.btn_clear = QPushButton("Vaciar historial")
        for b in (self.btn_open, self.btn_rerun, self.btn_delete):
            buttons.addWidget(b)
        buttons.addStretch(1)
        buttons.addWidget(self.btn_clear)

        self.btn_open.clicked.connect(lambda: self._emit(self.open_requested))
        self.btn_rerun.clicked.connect(lambda: self._emit(self.rerun_requested))
        self.btn_delete.clicked.connect(self._delete)
        self.btn_clear.clicked.connect(self._clear)

        layout = QVBoxLayout(self)
        layout.addWidget(self.table)
        layout.addLayout(buttons)
        self.reload()

    def reload(self) -> None:
        records = self.history.list()
        self.table.setRowCount(len(records))
        for row, rec in enumerate(records):
            duration = f"{rec.duration:.1f} s" if rec.duration is not None else ""
            values = [rec.started_text, rec.targets, str(rec.hosts_up), str(rec.open_ports), duration, rec.command]
            for col, val in enumerate(values):
                item = QTableWidgetItem(val)
                item.setData(Qt.ItemDataRole.UserRole, rec.id)
                self.table.setItem(row, col, item)
        self.table.resizeColumnsToContents()

    def _selected_id(self) -> int | None:
        items = self.table.selectedItems()
        return items[0].data(Qt.ItemDataRole.UserRole) if items else None

    def _emit(self, signal: Signal) -> None:
        scan_id = self._selected_id()
        if scan_id is not None:
            signal.emit(scan_id)

    def _delete(self) -> None:
        scan_id = self._selected_id()
        if scan_id is not None:
            self.history.delete(scan_id)
            self.reload()

    def _clear(self) -> None:
        answer = QMessageBox.question(self, "Vaciar historial", "¿Eliminar todos los escaneos guardados?")
        if answer == QMessageBox.StandardButton.Yes:
            self.history.clear()
            self.reload()
