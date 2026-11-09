"""Pantalla «Resultados»: resumen en tarjetas, lista de hosts y tabla de puertos."""

from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QAbstractItemView,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QPlainTextEdit,
    QPushButton,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from nmap_gui.core.parser import Host, Port, ScanResult

from ..theme import STATE_COLORS, color
from ..widgets import Card, PillDelegate, StatCard, ToggleSwitch
from .scan_page import page_header


class ResultsPage(QWidget):
    export_requested = Signal()
    import_requested = Signal()

    def __init__(self, theme: str, parent: QWidget | None = None):
        super().__init__(parent)
        self.setObjectName("Root")
        self._result: ScanResult | None = None
        self._theme = theme

        lay = QVBoxLayout(self)
        lay.setContentsMargins(28, 24, 28, 24)
        lay.setSpacing(16)

        head = QHBoxLayout()
        head.addWidget(page_header("Resultados", "Hosts encontrados y sus puertos."), 1)
        self.btn_import = QPushButton("Abrir XML…")
        self.btn_export = QPushButton("Exportar…")
        self.btn_export.setEnabled(False)
        head.addWidget(self.btn_import, 0, Qt.AlignmentFlag.AlignBottom)
        head.addWidget(self.btn_export, 0, Qt.AlignmentFlag.AlignBottom)
        lay.addLayout(head)

        stats = QHBoxLayout()
        stats.setSpacing(14)
        self.stat_hosts = StatCard("Hosts activos")
        self.stat_open = StatCard("Puertos abiertos")
        self.stat_services = StatCard("Servicios distintos")
        self.stat_time = StatCard("Duración")
        for s in (self.stat_hosts, self.stat_open, self.stat_services, self.stat_time):
            stats.addWidget(s)
        lay.addLayout(stats)

        # Hosts (izquierda)
        hosts_card = Card("Hosts")
        self.host_list = QListWidget()
        self.host_list.setMinimumWidth(240)
        hosts_card.body.addWidget(self.host_list)

        # Puertos (derecha)
        ports_card = Card()
        ph = QHBoxLayout()
        self.ports_title = QLabel("Puertos")
        self.ports_title.setObjectName("CardTitle")
        self.filter = QLineEdit()
        self.filter.setPlaceholderText("Buscar puerto o servicio…")
        self.filter.setClearButtonEnabled(True)
        self.filter.setMaximumWidth(240)
        self.only_open = ToggleSwitch("Solo abiertos")
        ph.addWidget(self.ports_title)
        ph.addStretch(1)
        ph.addWidget(self.filter)
        ph.addSpacing(8)
        ph.addWidget(self.only_open)
        ports_card.body.addLayout(ph)

        self.table = QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels(["Puerto", "Estado", "Servicio", "Versión / detalle"])
        self.table.verticalHeader().setVisible(False)
        self.table.setShowGrid(False)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.verticalHeader().setDefaultSectionSize(38)
        hdr = self.table.horizontalHeader()
        hdr.setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        hdr.setDefaultAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
        self.table.setColumnWidth(0, 110)
        self.table.setColumnWidth(1, 150)
        self.table.setColumnWidth(2, 130)
        self.pill = PillDelegate({}, self.table)
        self.table.setItemDelegateForColumn(1, self.pill)
        ports_card.body.addWidget(self.table, 1)

        self.detail = QPlainTextEdit()
        self.detail.setObjectName("Detail")
        self.detail.setReadOnly(True)
        self.detail.setMaximumHeight(130)
        self.detail.setPlaceholderText("Selecciona un puerto para ver detalles y salida de scripts.")
        ports_card.body.addWidget(self.detail)

        split = QSplitter(Qt.Orientation.Horizontal)
        split.addWidget(hosts_card)
        split.addWidget(ports_card)
        split.setStretchFactor(1, 1)
        split.setSizes([280, 760])
        lay.addWidget(split, 1)

        self.empty = QLabel("Aún no hay resultados. Ejecuta un escaneo o abre un XML de nmap.")
        self.empty.setObjectName("Muted")
        self.empty.setAlignment(Qt.AlignmentFlag.AlignCenter)
        lay.addWidget(self.empty)

        self.host_list.currentRowChanged.connect(self._show_host)
        self.filter.textChanged.connect(self._fill_ports)
        self.only_open.toggled.connect(self._fill_ports)
        self.table.currentCellChanged.connect(self._show_port)
        self.btn_export.clicked.connect(self.export_requested)
        self.btn_import.clicked.connect(self.import_requested)
        self.apply_theme(theme)
        self.set_result(None)

    def apply_theme(self, theme: str) -> None:
        self._theme = theme
        self.pill.colors = {k: color(theme, v) for k, v in STATE_COLORS.items()}
        self.pill.line = color(theme, "border")
        self.stat_hosts.set_accent(color(theme, "accent"))
        self.stat_open.set_accent(color(theme, "info"))
        self.stat_services.set_accent(color(theme, "warn"))
        self.only_open.set_colors(color(theme, "accent"), color(theme, "border"), color(theme, "text"),
                                  color(theme, "muted"))
        self.table.viewport().update()

    def set_result(self, result: ScanResult | None, exportable: bool = False) -> None:
        self._result = result
        self.btn_export.setEnabled(exportable)
        self.host_list.clear()
        has = bool(result and result.hosts)
        self.empty.setVisible(not has)
        if result is None:
            for s in (self.stat_hosts, self.stat_open, self.stat_services, self.stat_time):
                s.set_value("—")
            self.table.setRowCount(0)
            self.detail.clear()
            return
        open_ports = [p for h in result.hosts for p in h.open_ports]
        self.stat_hosts.set_value(f"{result.hosts_up}")
        self.stat_open.set_value(str(len(open_ports)))
        self.stat_services.set_value(str(len({p.service for p in open_ports if p.service})))
        self.stat_time.set_value(f"{result.elapsed:.1f} s")
        for host in result.hosts:
            sub = host.hostnames[0] if host.hostnames else (host.vendor or host.status)
            item = QListWidgetItem(f"{host.address}\n{sub} · {len(host.open_ports)} abiertos")
            item.setData(Qt.ItemDataRole.UserRole, host)
            item.setToolTip(host.best_os or host.address)
            self.host_list.addItem(item)
        if has:
            self.host_list.setCurrentRow(0)

    def _current_host(self) -> Host | None:
        item = self.host_list.currentItem()
        return item.data(Qt.ItemDataRole.UserRole) if item else None

    def _show_host(self, _row: int) -> None:
        host = self._current_host()
        if host is None:
            self.ports_title.setText("Puertos")
            self.table.setRowCount(0)
            return
        title = host.display_name
        if host.best_os:
            title += f"  ·  {host.best_os}"
        self.ports_title.setText(title)
        self._fill_ports()

    def _fill_ports(self) -> None:
        host = self._current_host()
        self.table.setRowCount(0)
        self.detail.clear()
        if host is None:
            return
        needle = self.filter.text().strip().lower()
        ports = [
            p for p in sorted(host.ports, key=lambda p: (p.protocol, p.portid))
            if (not self.only_open.isChecked() or p.state == "open")
            and (not needle or needle in f"{p.portid} {p.protocol} {p.service} {p.service_detail}".lower())
        ]
        self.table.setRowCount(len(ports))
        for row, p in enumerate(ports):
            values = [f"{p.portid}/{p.protocol}", p.state, p.service, p.service_detail]
            for col, val in enumerate(values):
                it = QTableWidgetItem(val)
                it.setData(Qt.ItemDataRole.UserRole, p)
                self.table.setItem(row, col, it)
        if not ports:
            self.detail.setPlainText("Este host no tiene puertos que coincidan con el filtro.")

    def _show_port(self, row: int, *_args) -> None:
        item = self.table.item(row, 0) if row >= 0 else None
        p: Port | None = item.data(Qt.ItemDataRole.UserRole) if item else None
        if p is None:
            return
        lines = [f"{p.portid}/{p.protocol} — {p.state} ({p.reason})", f"Servicio: {p.service} {p.service_detail}".rstrip()]
        for sid, out in p.scripts.items():
            lines += ["", f"[{sid}]", out.strip()]
        self.detail.setPlainText("\n".join(lines))
