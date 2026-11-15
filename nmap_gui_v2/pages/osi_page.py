"""Pantalla «Modelo OSI»: la red vista capa por capa, con modo aprendizaje."""

from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QComboBox,
    QFrame,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

from ..core.analysis import Analysis
from ..core.findings import SEVERITY_LABELS, worst
from ..core.osi import LayerSummary, build_osi
from ..theme import THEMES
from ..widgets import FlowLayout, ToggleSwitch, tag
from .scan_page import page_header
from .topology_page import RISK_COLOR_KEY, RISK_TAG


class LayerCard(QFrame):
    investigate = Signal(int)

    def __init__(self, summary: LayerSummary, theme: str, explain: bool, expanded: bool):
        super().__init__()
        self.summary = summary
        self.number = summary.layer.number
        self.setObjectName("CardActive" if expanded else "Card")
        layer = summary.layer
        v = QVBoxLayout(self)
        v.setContentsMargins(18, 14, 18, 14)
        v.setSpacing(12)

        head = QHBoxLayout()
        head.setSpacing(14)
        self.badge = QLabel(str(layer.number))
        self.badge.setObjectName("LayerBadgeActive" if expanded else "LayerBadge")
        self.badge.setAlignment(Qt.AlignmentFlag.AlignCenter)
        head.addWidget(self.badge)
        names = QVBoxLayout()
        names.setSpacing(0)
        title = QLabel(layer.name)
        title.setObjectName("CardTitle")
        sub = QLabel(layer.subtitle)
        sub.setObjectName("Muted")
        names.addWidget(title)
        names.addWidget(sub)
        name_box = QWidget()
        name_box.setLayout(names)
        name_box.setFixedWidth(190)
        head.addWidget(name_box)

        chips = QWidget()
        flow = FlowLayout(chips)
        for proto in summary.protocols:
            variant = "danger" if any(x in proto for x in ("1.0", "1.1", "SSL", "Telnet")) else ""
            flow.addWidget(tag(proto, variant))
        if not summary.protocols:
            flow.addWidget(tag("Nada detectado" if layer.number != 1 else "No visible para nmap"))
        head.addWidget(chips, 1)

        count = len(summary.findings)
        risk = worst(summary.findings)
        pill = tag(f"{count} · {SEVERITY_LABELS[risk].lower()}" if count else "Sin hallazgos", RISK_TAG.get(risk, ""))
        head.addWidget(pill, 0, Qt.AlignmentFlag.AlignVCenter)

        self.toggle = QPushButton("Ocultar" if expanded else "Ver detalle")
        self.toggle.setObjectName("LinkButton")
        self.toggle.setCursor(Qt.CursorShape.PointingHandCursor)
        self.toggle.setAccessibleName(f"Detalle de la capa {layer.number}, {layer.name}")
        head.addWidget(self.toggle)
        v.addLayout(head)

        self.body = QWidget()
        b = QHBoxLayout(self.body)
        b.setContentsMargins(0, 0, 0, 0)
        b.setSpacing(16)
        if explain:
            col = QVBoxLayout()
            lbl = QLabel("¿QUÉ PASA EN ESTA CAPA?")
            lbl.setObjectName("SectionLabel")
            txt = QLabel(layer.explanation)
            txt.setWordWrap(True)
            col.addWidget(lbl)
            col.addWidget(txt)
            tools = QLabel("Herramientas: " + " · ".join(layer.tools))
            tools.setObjectName("Muted")
            tools.setWordWrap(True)
            col.addWidget(tools)
            col.addStretch(1)
            b.addLayout(col, 1)

        col = QVBoxLayout()
        lbl = QLabel("EN TU RED")
        lbl.setObjectName("SectionLabel")
        col.addWidget(lbl)
        c = THEMES[theme]
        for f in summary.findings:
            box = QLabel(f"<b>{f.severity_label} · {f.title}</b> — {f.host} {f.port}<br>{f.detail}<br>"
                         f"<span style='color:{c['accent']}'>Qué hacer:</span> {f.recommendation}")
            box.setObjectName("Inset")
            box.setWordWrap(True)
            box.setContentsMargins(10, 8, 10, 8)
            box.setStyleSheet(f"#Inset {{ border-left: 3px solid {c[RISK_COLOR_KEY[f.severity]]}; }}")
            col.addWidget(box)
        if not summary.findings:
            none = QLabel("No hay hallazgos en esta capa." if layer.number != 1 else
                          "Revisa a mano quién puede conectar un cable o alcanzar tu Wi‑Fi.")
            none.setObjectName("Muted")
            none.setWordWrap(True)
            col.addWidget(none)
        if layer.suggestion_text:
            self.btn = QPushButton(f"Investigar esta capa: {layer.suggestion_text}")
            self.btn.setToolTip("Prepara este escaneo en la pantalla Escanear")
            self.btn.clicked.connect(lambda: self.investigate.emit(self.number))
            col.addWidget(self.btn, 0, Qt.AlignmentFlag.AlignLeft)
        col.addStretch(1)
        b.addLayout(col, 1)
        self.body.setVisible(expanded)
        v.addWidget(self.body)

        self.toggle.clicked.connect(self._toggle)

    def _toggle(self) -> None:
        self.set_expanded(self.body.isHidden())

    def set_expanded(self, on: bool) -> None:
        self.body.setVisible(on)
        self.toggle.setText("Ocultar" if on else "Ver detalle")
        self.setObjectName("CardActive" if on else "Card")
        self.badge.setObjectName("LayerBadgeActive" if on else "LayerBadge")
        for w in (self, self.badge):
            w.style().unpolish(w)
            w.style().polish(w)


class OsiPage(QWidget):
    investigate = Signal(int, str)  # capa, objetivo ("" = los del último escaneo)
    demo_requested = Signal()

    def __init__(self, theme: str, parent: QWidget | None = None):
        super().__init__(parent)
        self.setObjectName("Root")
        self.theme = theme
        self.analysis = Analysis()
        self.cards: list[LayerCard] = []

        outer = QVBoxLayout(self)
        outer.setContentsMargins(28, 24, 28, 24)
        outer.setSpacing(14)

        head = QHBoxLayout()
        head.addWidget(page_header(
            "Tu red, capa por capa",
            "Cada protocolo y hallazgo se ubica en la capa del modelo OSI donde ocurre."), 1)
        self.host = QComboBox()
        self.host.setMinimumWidth(220)
        self.host.setAccessibleName("Equipo a mostrar")
        self.explain = ToggleSwitch("Modo aprendizaje")
        self.explain.setChecked(True)
        head.addWidget(self.host, 0, Qt.AlignmentFlag.AlignBottom)
        head.addSpacing(10)
        head.addWidget(self.explain, 0, Qt.AlignmentFlag.AlignBottom)
        outer.addLayout(head)

        self.scroll = QScrollArea()
        self.scroll.setWidgetResizable(True)
        self.scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.list = QWidget()
        self.list.setObjectName("Root")
        self.list_layout = QVBoxLayout(self.list)
        self.list_layout.setContentsMargins(0, 0, 4, 0)
        self.list_layout.setSpacing(10)
        self.scroll.setWidget(self.list)
        outer.addWidget(self.scroll, 1)

        self.host.currentIndexChanged.connect(self._render)
        self.explain.toggled.connect(self._render)
        self.set_analysis(self.analysis)

    def current_host(self) -> str:
        return self.host.currentData() or ""

    def set_analysis(self, analysis: Analysis) -> None:
        self.analysis = analysis
        self.host.blockSignals(True)
        self.host.clear()
        self.host.addItem("Toda la red", "")
        if analysis.result:
            for h in analysis.result.hosts:
                if h.status == "up":
                    self.host.addItem(h.display_name, h.address)
        self.host.blockSignals(False)
        self._render()

    def focus_host(self, ip: str) -> None:
        idx = self.host.findData(ip)
        self.host.setCurrentIndex(max(0, idx))

    def apply_theme(self, theme: str) -> None:
        self.theme = theme
        self._render()

    def _render(self) -> None:
        open_layers = {c.number for c in self.cards if not c.body.isHidden()}
        while self.list_layout.count():
            item = self.list_layout.takeAt(0)
            w = item.widget()
            if w:
                w.hide()
                w.setParent(None)
                w.deleteLater()
        a = self.analysis
        host = self.current_host() or None
        summaries = build_osi(a.result, a.extras, a.findings, host)
        if not open_layers:
            # Al abrir: se despliega la capa con el hallazgo más grave.
            with_f = [s for s in summaries if s.findings]
            if with_f:
                best = min(with_f, key=lambda s: ("critico", "alto", "medio", "bajo").index(worst(s.findings)))
                open_layers = {best.layer.number}
        self.cards = []
        for s in summaries:
            card = LayerCard(s, self.theme, self.explain.isChecked(), s.layer.number in open_layers)
            card.investigate.connect(lambda n: self.investigate.emit(n, self.current_host()))
            self.cards.append(card)
            self.list_layout.addWidget(card)
        if a.result is None:
            note = QLabel("Ejecuta un escaneo o abre un XML para ver tu red en cada capa. "
                          "Mientras tanto, abre cualquier capa para aprender qué hace.")
            note.setObjectName("Muted")
            note.setWordWrap(True)
            demo = QPushButton("Ver red de ejemplo")
            demo.setObjectName("AccentButton")
            demo.clicked.connect(self.demo_requested)
            self.list_layout.insertWidget(0, demo, 0, Qt.AlignmentFlag.AlignLeft)
            self.list_layout.insertWidget(0, note)
        self.list_layout.addStretch(1)

    def card(self, number: int) -> LayerCard:
        return next(c for c in self.cards if c.number == number)
