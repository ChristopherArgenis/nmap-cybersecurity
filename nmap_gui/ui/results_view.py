"""Vista de resultados: árbol de hosts y puertos con filtro."""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtGui import QBrush, QColor
from PySide6.QtWidgets import (
    QCheckBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QSplitter,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from ..core.parser import Host, Port, ScanResult

_STATE_COLORS = {"open": "#1a9e55", "closed": "#d64545", "filtered": "#d08a10", "up": "#1a9e55", "down": "#d64545"}


class ResultsView(QWidget):
    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent)
        self._result: ScanResult | None = None

        top = QHBoxLayout()
        self.summary = QLabel("Sin resultados todavía.")
        self.summary.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        top.addWidget(self.summary, 1)
        self.filter = QLineEdit()
        self.filter.setPlaceholderText("Filtrar por host, puerto o servicio…")
        self.filter.setClearButtonEnabled(True)
        self.filter.setMaximumWidth(280)
        top.addWidget(self.filter)
        self.only_open = QCheckBox("Solo abiertos")
        top.addWidget(self.only_open)

        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["Host / Puerto", "Estado", "Servicio", "Detalle"])
        self.tree.setAlternatingRowColors(True)
        self.tree.setSortingEnabled(True)
        self.tree.sortByColumn(0, Qt.SortOrder.AscendingOrder)
        self.tree.setColumnWidth(0, 240)
        self.tree.setColumnWidth(1, 90)
        self.tree.setColumnWidth(2, 120)

        self.detail = QPlainTextEdit()
        self.detail.setReadOnly(True)
        self.detail.setPlaceholderText("Selecciona un host o puerto para ver detalles.")

        split = QSplitter(Qt.Orientation.Vertical)
        split.addWidget(self.tree)
        split.addWidget(self.detail)
        split.setStretchFactor(0, 3)
        split.setStretchFactor(1, 1)

        layout = QVBoxLayout(self)
        layout.addLayout(top)
        layout.addWidget(split)

        self.filter.textChanged.connect(self._refresh)
        self.only_open.toggled.connect(self._refresh)
        self.tree.currentItemChanged.connect(self._show_detail)

    def set_result(self, result: ScanResult | None) -> None:
        self._result = result
        if result is None:
            self.summary.setText("El escaneo no produjo resultados estructurados.")
        else:
            open_count = sum(len(h.open_ports) for h in result.hosts)
            self.summary.setText(
                f"Hosts activos: {result.hosts_up} · inactivos: {result.hosts_down} · "
                f"puertos abiertos: {open_count} · {result.elapsed:.1f} s"
            )
        self._refresh()

    def clear(self) -> None:
        self._result = None
        self.tree.clear()
        self.detail.clear()
        self.summary.setText("Escaneando…")

    def _refresh(self) -> None:
        self.tree.clear()
        if not self._result:
            return
        needle = self.filter.text().strip().lower()
        only_open = self.only_open.isChecked()
        self.tree.setSortingEnabled(False)
        for host in self._result.hosts:
            ports = [p for p in host.ports if not only_open or p.state == "open"]
            host_text = f"{host.display_name} {host.best_os}".lower()
            if needle and needle not in host_text:
                ports = [p for p in ports if needle in _port_text(p)]
                if not ports:
                    continue
            h_item = QTreeWidgetItem([host.display_name, host.status, host.best_os, host.vendor])
            h_item.setData(0, Qt.ItemDataRole.UserRole, host)
            _color(h_item, host.status)
            font = h_item.font(0)
            font.setBold(True)
            h_item.setFont(0, font)
            for p in ports:
                p_item = PortItem([f"{p.portid}/{p.protocol}", p.state, p.service, p.service_detail])
                p_item.setData(0, Qt.ItemDataRole.UserRole, p)
                _color(p_item, p.state)
                h_item.addChild(p_item)
            self.tree.addTopLevelItem(h_item)
            h_item.setExpanded(True)
        self.tree.setSortingEnabled(True)

    def _show_detail(self, item: QTreeWidgetItem | None, _prev=None) -> None:
        if item is None:
            self.detail.clear()
            return
        obj = item.data(0, Qt.ItemDataRole.UserRole)
        if isinstance(obj, Host):
            lines = [f"Dirección: {obj.address} ({obj.addr_type})", f"Estado: {obj.status}"]
            if obj.hostnames:
                lines.append("Nombres: " + ", ".join(obj.hostnames))
            if obj.mac:
                lines.append(f"MAC: {obj.mac} {obj.vendor}")
            if obj.os_matches:
                lines.append("Sistema operativo probable:")
                lines += [f"  {name} — {acc}%" for name, acc in obj.os_matches[:5]]
            lines.append(f"Puertos abiertos: {len(obj.open_ports)} de {len(obj.ports)} reportados")
        elif isinstance(obj, Port):
            lines = [
                f"Puerto: {obj.portid}/{obj.protocol}",
                f"Estado: {obj.state} ({obj.reason})",
                f"Servicio: {obj.service} {obj.service_detail}".rstrip(),
            ]
            for sid, out in obj.scripts.items():
                lines += ["", f"[{sid}]", out.strip()]
        else:
            lines = []
        self.detail.setPlainText("\n".join(lines))


class PortItem(QTreeWidgetItem):
    """Ordena la columna de puerto numéricamente (22 antes que 443)."""

    def __lt__(self, other: QTreeWidgetItem) -> bool:
        col = self.treeWidget().sortColumn() if self.treeWidget() else 0
        if col == 0:
            a, b = self.data(0, Qt.ItemDataRole.UserRole), other.data(0, Qt.ItemDataRole.UserRole)
            if isinstance(a, Port) and isinstance(b, Port):
                return (a.portid, a.protocol) < (b.portid, b.protocol)
        return super().__lt__(other)


def _port_text(p: Port) -> str:
    return f"{p.portid} {p.protocol} {p.state} {p.service} {p.service_detail}".lower()


def _color(item: QTreeWidgetItem, state: str) -> None:
    color = _STATE_COLORS.get(state.split("|")[0])
    if color:
        item.setForeground(1, QBrush(QColor(color)))
