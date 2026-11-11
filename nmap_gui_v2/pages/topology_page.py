"""Pantalla «Topología»: mapa de la red deducido del escaneo."""

from __future__ import annotations

from PySide6.QtCore import QRectF, Qt, Signal
from PySide6.QtGui import QBrush, QColor, QFont, QImage, QPainter, QPainterPath, QPen
from PySide6.QtWidgets import (
    QFileDialog,
    QGraphicsItem,
    QGraphicsObject,
    QGraphicsScene,
    QGraphicsView,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QScrollArea,
    QSplitter,
    QVBoxLayout,
    QWidget,
)

from ..core.analysis import Analysis
from ..core.findings import SEVERITY_LABELS
from ..core.topology import NODE_H, NODE_W, ZONE_LABELS, Node, layout
from ..theme import THEMES
from ..widgets import Card, FlowLayout, ToggleSwitch, tag
from .scan_page import page_header

RISK_COLOR_KEY = {"critico": "danger", "alto": "danger", "medio": "warn", "bajo": "info"}
RISK_TAG = {"critico": "danger", "alto": "danger", "medio": "warn", "bajo": "info"}


class NodeItem(QGraphicsObject):
    """Un equipo del mapa: tarjeta redondeada con borde del color de su riesgo."""

    def __init__(self, node: Node, colors: dict[str, str]):
        super().__init__()
        self.node = node
        self.colors = colors
        self.dimmed = False
        self.setFlag(QGraphicsItem.GraphicsItemFlag.ItemIsSelectable)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setToolTip(f"{node.kind_label}\n{node.sublabel}".strip())

    def boundingRect(self) -> QRectF:  # noqa: N802
        return QRectF(-NODE_W / 2 - 4, -NODE_H / 2 - 4, NODE_W + 8, NODE_H + 8)

    def paint(self, painter: QPainter, _option, _widget=None) -> None:
        c = self.colors
        virtual = self.node.kind in ("internet", "hub", "hop")
        rect = QRectF(-NODE_W / 2, -NODE_H / 2, NODE_W, NODE_H)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.setOpacity(0.28 if self.dimmed else 1.0)

        border = QColor(c["border"])
        width = 1.2
        if self.node.risk:
            border = QColor(c[RISK_COLOR_KEY[self.node.risk]])
            width = 2.2
        if self.node.kind == "gateway":
            border, width = QColor(c["accent"]), 2.0
        if self.isSelected():
            border, width = QColor(c["accent"]), 3.2
        fill = QColor(c["card2"] if virtual else c["card"])
        pen = QPen(border, width)
        if virtual:
            pen.setStyle(Qt.PenStyle.DashLine)
        painter.setPen(pen)
        painter.setBrush(QBrush(fill))
        painter.drawRoundedRect(rect, 12, 12)

        painter.setPen(QColor(c["muted"]))
        f = QFont(painter.font())
        f.setPointSizeF(7.5)
        f.setBold(True)
        f.setLetterSpacing(QFont.SpacingType.AbsoluteSpacing, 0.6)
        painter.setFont(f)
        top = self.node.kind_label.upper()
        if self.node.findings:
            top += f" · {self.node.findings}"
        top = painter.fontMetrics().elidedText(top, Qt.TextElideMode.ElideRight, NODE_W - 36)
        painter.drawText(rect.adjusted(12, 7, -12, 0), Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignTop, top)

        painter.setPen(QColor(c["text"]))
        f.setPointSizeF(10.5)
        f.setLetterSpacing(QFont.SpacingType.AbsoluteSpacing, 0)
        painter.setFont(f)
        painter.drawText(rect.adjusted(12, 22, -12, 0), Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignTop,
                         painter.fontMetrics().elidedText(self.node.label, Qt.TextElideMode.ElideRight, NODE_W - 24))

        painter.setPen(QColor(c["accent"] if self.node.kind == "gateway" else c["muted"]))
        f.setBold(False)
        f.setFamilies(["Cascadia Code", "JetBrains Mono", "Consolas", "monospace"])
        f.setPointSizeF(8.5)
        painter.setFont(f)
        painter.drawText(rect.adjusted(12, 0, -12, -8), Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignBottom,
                         self.node.sublabel)

        if self.node.risk:
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(QColor(c[RISK_COLOR_KEY[self.node.risk]]))
            painter.drawEllipse(QRectF(NODE_W / 2 - 18, -NODE_H / 2 + 9, 8, 8))


class MapView(QGraphicsView):
    def __init__(self, scene: QGraphicsScene):
        super().__init__(scene)
        self.setRenderHints(QPainter.RenderHint.Antialiasing | QPainter.RenderHint.TextAntialiasing)
        self.setDragMode(QGraphicsView.DragMode.ScrollHandDrag)
        self.setTransformationAnchor(QGraphicsView.ViewportAnchor.AnchorUnderMouse)
        self.setMinimumHeight(420)

    def wheelEvent(self, event) -> None:  # noqa: N802
        factor = 1.15 if event.angleDelta().y() > 0 else 1 / 1.15
        scale = self.transform().m11() * factor
        if 0.25 <= scale <= 3.0:
            self.scale(factor, factor)

    def fit(self) -> None:
        rect = self.scene().itemsBoundingRect().adjusted(-40, -40, 40, 40)
        if rect.isValid():
            self.fitInView(rect, Qt.AspectRatioMode.KeepAspectRatio)
            if self.transform().m11() > 1.2:
                self.resetTransform()
                self.scale(1.2, 1.2)
                self.centerOn(rect.center())


class TopologyPage(QWidget):
    scan_host = Signal(str)
    show_osi = Signal(str)
    demo_requested = Signal()

    def __init__(self, theme: str, parent: QWidget | None = None):
        super().__init__(parent)
        self.setObjectName("Root")
        self.theme = theme
        self.analysis = Analysis()
        self.items: dict[str, NodeItem] = {}
        self._selected: Node | None = None

        lay = QVBoxLayout(self)
        lay.setContentsMargins(28, 24, 28, 24)
        lay.setSpacing(16)

        head = QHBoxLayout()
        head.addWidget(page_header("Topología de red", "Mapa deducido del último escaneo. Arrastra para moverte y usa la rueda para acercar."), 1)
        self.only_findings = ToggleSwitch("Solo con hallazgos")
        self.btn_fit = QPushButton("Ajustar")
        self.btn_png = QPushButton("Exportar PNG")
        head.addWidget(self.only_findings, 0, Qt.AlignmentFlag.AlignBottom)
        head.addSpacing(8)
        head.addWidget(self.btn_fit, 0, Qt.AlignmentFlag.AlignBottom)
        head.addWidget(self.btn_png, 0, Qt.AlignmentFlag.AlignBottom)
        lay.addLayout(head)

        map_card = Card(shadow=False)
        map_card.body.setContentsMargins(8, 8, 8, 8)
        self.scene = QGraphicsScene(self)
        self.view = MapView(self.scene)
        map_card.body.addWidget(self.view, 1)
        self.legend = QLabel()
        self.legend.setObjectName("Muted")
        self.legend.setWordWrap(True)
        map_card.body.addWidget(self.legend)

        self.detail = self._build_detail()

        split = QSplitter(Qt.Orientation.Horizontal)
        split.addWidget(map_card)
        split.addWidget(self.detail)
        split.setStretchFactor(0, 1)
        split.setSizes([820, 330])
        lay.addWidget(split, 1)

        self.empty = QLabel("Aún no hay mapa. Ejecuta un escaneo o abre un XML de nmap.")
        self.empty.setObjectName("Muted")
        self.empty.setAlignment(Qt.AlignmentFlag.AlignCenter)
        lay.addWidget(self.empty)
        self.btn_demo = QPushButton("Ver red de ejemplo")
        self.btn_demo.setObjectName("AccentButton")
        self.btn_demo.setToolTip("Muestra una red de casa ficticia, sin escanear nada")
        self.btn_demo.clicked.connect(self.demo_requested)
        lay.addWidget(self.btn_demo, 0, Qt.AlignmentFlag.AlignCenter)

        self.scene.selectionChanged.connect(self._on_selection)
        self.only_findings.toggled.connect(self._apply_filter)
        self.btn_fit.clicked.connect(self.view.fit)
        self.btn_png.clicked.connect(self.export_png)
        self.btn_scan.clicked.connect(lambda: self._selected and self.scan_host.emit(self._selected.ip))
        self.btn_osi.clicked.connect(lambda: self._selected and self.show_osi.emit(self._selected.ip))
        self.set_analysis(self.analysis)

    # ------------------------------------------------------------ detalle
    def _build_detail(self) -> QScrollArea:
        area = QScrollArea()
        area.setWidgetResizable(True)
        area.setMinimumWidth(300)
        area.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        card = Card(shadow=False)
        self.d_kind = QLabel()
        self.d_kind.setObjectName("SectionLabel")
        self.d_title = QLabel("Selecciona un equipo")
        self.d_title.setObjectName("PageTitle")
        self.d_title.setWordWrap(True)
        self.d_ip = QLabel("Haz clic en cualquier equipo del mapa para ver sus datos.")
        self.d_ip.setObjectName("Muted")
        self.d_ip.setWordWrap(True)
        for w in (self.d_kind, self.d_title, self.d_ip):
            card.body.addWidget(w)

        self.d_grid = QGridLayout()
        self.d_grid.setHorizontalSpacing(12)
        self.d_grid.setVerticalSpacing(6)
        self.d_values: dict[str, QLabel] = {}
        for row, key in enumerate(("MAC", "Fabricante", "Sistema", "Hallazgos")):
            k = QLabel(key)
            k.setObjectName("Muted")
            v = QLabel("—")
            v.setWordWrap(True)
            v.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            self.d_grid.addWidget(k, row, 0, Qt.AlignmentFlag.AlignTop)
            self.d_grid.addWidget(v, row, 1)
            self.d_values[key] = v
        self.d_grid.setColumnStretch(1, 1)
        card.body.addLayout(self.d_grid)

        self.d_ports_label = QLabel("PUERTOS ABIERTOS")
        self.d_ports_label.setObjectName("SectionLabel")
        card.body.addWidget(self.d_ports_label)
        self.d_ports_box = QWidget()
        self.d_ports = FlowLayout(self.d_ports_box)
        card.body.addWidget(self.d_ports_box)

        self.d_find_label = QLabel("HALLAZGOS")
        self.d_find_label.setObjectName("SectionLabel")
        card.body.addWidget(self.d_find_label)
        self.d_findings = QVBoxLayout()
        self.d_findings.setSpacing(8)
        card.body.addLayout(self.d_findings)

        self.btn_scan = QPushButton("Escanear este equipo")
        self.btn_scan.setObjectName("AccentButton")
        self.btn_osi = QPushButton("Ver por capas OSI")
        card.body.addWidget(self.btn_scan)
        card.body.addWidget(self.btn_osi)
        card.body.addStretch(1)
        area.setWidget(card)
        return area

    def _show_detail(self, node: Node | None) -> None:
        self._selected = node if node and node.host else None
        has = self._selected is not None
        for w in (self.d_ports_label, self.d_ports_box, self.d_find_label, self.btn_scan, self.btn_osi):
            w.setVisible(has)
        for i in range(self.d_grid.count()):
            self.d_grid.itemAt(i).widget().setVisible(has)
        self.d_ports.clear()
        _clear(self.d_findings)
        if node is None:
            self.d_kind.setText("")
            self.d_title.setText("Selecciona un equipo")
            self.d_ip.setText("Haz clic en cualquier equipo del mapa para ver sus datos.")
            return
        if not has:
            self.d_kind.setText(node.kind_label.upper())
            self.d_title.setText(node.label)
            self.d_ip.setText(node.sublabel or "Nodo deducido, no escaneado.")
            return
        h = node.host
        risk = f" · {SEVERITY_LABELS[node.risk].upper()}" if node.risk else ""
        self.d_kind.setText(node.kind_label.upper() + risk)
        self.d_title.setText(node.label)
        self.d_ip.setText(", ".join([h.address, *h.hostnames]))
        self.d_values["MAC"].setText(h.mac or "—")
        self.d_values["Fabricante"].setText(h.vendor or "—")
        self.d_values["Sistema"].setText(h.best_os or "—")
        self.d_values["Hallazgos"].setText(str(node.findings) if node.findings else "Ninguno")
        open_ports = [p for p in h.ports if p.state == "open"]
        for p in sorted(open_ports, key=lambda p: (p.protocol, p.portid)):
            self.d_ports.addWidget(tag(f"{p.portid}/{p.protocol} {p.service}".strip()))
        if not open_ports:
            self.d_ports.addWidget(tag("Ninguno visible"))
        mine = [f for f in self.analysis.findings if f.host == h.address]
        for f in mine:
            box = QLabel(f"<b>{f.severity_label} · {f.title}</b><br>{f.recommendation}")
            box.setObjectName("Inset")
            box.setWordWrap(True)
            box.setContentsMargins(10, 8, 10, 8)
            c = THEMES[self.theme][RISK_COLOR_KEY[f.severity]]
            box.setStyleSheet(f"#Inset {{ border-left: 3px solid {c}; }}")
            self.d_findings.addWidget(box)
        if not mine:
            self.d_findings.addWidget(QLabel("Sin hallazgos en este equipo."))

    # --------------------------------------------------------------- mapa
    def set_analysis(self, analysis: Analysis) -> None:
        self.analysis = analysis
        self._render()
        self.view.fit()

    def apply_theme(self, theme: str) -> None:
        self.theme = theme
        selected = self._selected.id if self._selected else None
        self._render()
        if selected and selected in self.items:
            self.items[selected].setSelected(True)

    def _render(self) -> None:
        c = THEMES[self.theme]
        self.scene.blockSignals(True)
        self.scene.clear()
        self.scene.blockSignals(False)
        self.items = {}
        topo = self.analysis.topology
        has = bool(topo.nodes)
        self.empty.setVisible(not has)
        self.btn_demo.setVisible(not has)
        self.view.setBackgroundBrush(QColor(self._map_bg()))
        self._show_detail(None)
        if not has:
            self.legend.setText("")
            return

        lay = layout(topo)
        for zone, (x, y, w, h) in lay.zones.items():
            path = QPainterPath()
            path.addRoundedRect(QRectF(x, y, w, h), 16, 16)
            color = QColor(c["warn"] if zone == "iot" else c["border"])
            pen = QPen(color, 1.2, Qt.PenStyle.DashLine)
            item = self.scene.addPath(path, pen, QBrush(Qt.BrushStyle.NoBrush))
            item.setZValue(-2)
            label = self.scene.addSimpleText(ZONE_LABELS[zone].upper())
            label.setBrush(QColor(c["warn"] if zone == "iot" else c["muted"]))
            f = QFont(label.font())
            f.setPointSizeF(7.5)
            f.setBold(True)
            label.setFont(f)
            label.setPos(x + 14, y + 6)
            label.setZValue(-2)

        for e in topo.edges:
            if e.a not in lay.positions or e.b not in lay.positions:
                continue
            (x1, y1), (x2, y2) = lay.positions[e.a], lay.positions[e.b]
            edge = QColor(c["muted"])
            edge.setAlpha(120)
            pen = QPen(edge, 1.5)
            if "hop:" in e.a or "hop:" in e.b:
                pen.setStyle(Qt.PenStyle.DashLine)
            line = self.scene.addLine(x1, y1, x2, y2, pen)
            line.setZValue(-1)

        for node in topo.nodes:
            if node.id not in lay.positions:
                continue
            item = NodeItem(node, c)
            item.setPos(*lay.positions[node.id])
            self.scene.addItem(item)
            self.items[node.id] = item

        hosts = [n for n in topo.nodes if n.host]
        risky = sum(1 for n in hosts if n.risk)
        subnet = f" · red {topo.subnet}" if topo.subnet else ""
        self.legend.setText(
            f"{len(hosts)} equipos{subnet} · {risky} con hallazgos.  "
            "Borde rojo: alto o crítico · ámbar: medio · azul: bajo · punteado: deducido, no escaneado"
        )
        self._apply_filter()

    def _map_bg(self) -> str:
        c = THEMES[self.theme]
        return c["console"] if self.theme == "oscuro" else c["bg"]

    def _apply_filter(self) -> None:
        only = self.only_findings.isChecked()
        for item in self.items.values():
            item.dimmed = only and item.node.host is not None and not item.node.findings
            item.update()

    def _on_selection(self) -> None:
        sel = [i for i in self.scene.selectedItems() if isinstance(i, NodeItem)]
        self._show_detail(sel[0].node if sel else None)

    def select(self, node_id: str) -> None:
        item = self.items.get(node_id)
        if item:
            self.scene.clearSelection()
            item.setSelected(True)
            self.view.centerOn(item)

    def export_png(self, path: str | None = None) -> str | None:
        if not self.items:
            return None
        if path is None:
            path, _ = QFileDialog.getSaveFileName(self, "Exportar mapa", "topologia.png", "Imagen PNG (*.png)")
            if not path:
                return None
        rect = self.scene.itemsBoundingRect().adjusted(-40, -40, 40, 40)
        img = QImage(int(rect.width() * 2), int(rect.height() * 2), QImage.Format.Format_ARGB32)
        img.fill(QColor(self._map_bg()))
        painter = QPainter(img)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        self.scene.render(painter, QRectF(img.rect()), rect)
        painter.end()
        img.save(path)
        return path


def _clear(layout) -> None:
    while layout.count():
        item = layout.takeAt(0)
        if item.widget():
            item.widget().deleteLater()
