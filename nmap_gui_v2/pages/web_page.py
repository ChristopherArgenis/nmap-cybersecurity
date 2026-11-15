"""Pantalla «Auditoría web»: cifrado, certificados y cabeceras de los paneles web."""

from __future__ import annotations

import html

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QBrush, QColor
from PySide6.QtWidgets import (
    QAbstractItemView,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QProgressBar,
    QPushButton,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from ..core.findings import SEVERITY_LABELS
from ..core.webaudit import SECURITY_HEADERS, WebResult, WebTarget
from ..theme import THEMES
from ..widgets import Card
from .scan_page import page_header
from .topology_page import RISK_COLOR_KEY

COLUMNS = ["Servicio", "Equipo", "Cifrado", "Certificado", "HTTPS", "Cabeceras", "Hallazgos"]


class WebAuditPage(QWidget):
    audit_requested = Signal()
    cancel_requested = Signal()
    demo_requested = Signal()

    def __init__(self, theme: str, parent: QWidget | None = None):
        super().__init__(parent)
        self.setObjectName("Root")
        self.theme = theme
        self.targets: list[WebTarget] = []
        self.results: dict[WebTarget, WebResult] = {}

        lay = QVBoxLayout(self)
        lay.setContentsMargins(28, 24, 28, 24)
        lay.setSpacing(14)

        head = QHBoxLayout()
        head.addWidget(page_header(
            "Auditoría web y TLS",
            "Revisa los paneles web que encontró nmap: cifrado, certificado, HTTPS y cabeceras de seguridad."), 1)
        self.btn_audit = QPushButton("Auditar servicios web")
        self.btn_audit.setObjectName("AccentButton")
        self.btn_cancel = QPushButton("Detener")
        self.btn_cancel.setVisible(False)
        head.addWidget(self.btn_audit, 0, Qt.AlignmentFlag.AlignBottom)
        head.addWidget(self.btn_cancel, 0, Qt.AlignmentFlag.AlignBottom)
        lay.addLayout(head)

        self.notice = QLabel()
        self.notice.setObjectName("Muted")
        self.notice.setWordWrap(True)
        lay.addWidget(self.notice)
        self.progress = QProgressBar()
        self.progress.setTextVisible(False)
        self.progress.setVisible(False)
        lay.addWidget(self.progress)

        table_card = Card(shadow=False)
        self.table = QTableWidget(0, len(COLUMNS))
        self.table.setHorizontalHeaderLabels(COLUMNS)
        self.table.verticalHeader().setVisible(False)
        self.table.verticalHeader().setDefaultSectionSize(36)
        self.table.setShowGrid(False)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        hdr = self.table.horizontalHeader()
        hdr.setDefaultAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
        hdr.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        table_card.body.addWidget(self.table)

        detail_card = Card(shadow=False)
        self.detail = QLabel("Selecciona un servicio para ver el detalle.")
        self.detail.setWordWrap(True)
        self.detail.setTextFormat(Qt.TextFormat.RichText)
        self.detail.setAlignment(Qt.AlignmentFlag.AlignTop | Qt.AlignmentFlag.AlignLeft)
        self.detail.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        detail_card.body.addWidget(self.detail, 1)

        self.split = QSplitter(Qt.Orientation.Vertical)
        self.split.addWidget(table_card)
        self.split.addWidget(detail_card)
        self.split.setSizes([360, 300])
        lay.addWidget(self.split, 1)

        self.empty = QWidget()
        eb = QVBoxLayout(self.empty)
        eb.addStretch(1)
        msg = QLabel("No hay servicios web en el escaneo actual.\n"
                     "Ejecuta un escaneo con detección de servicios (-sV) o mira la red de ejemplo.")
        msg.setObjectName("Muted")
        msg.setAlignment(Qt.AlignmentFlag.AlignCenter)
        demo = QPushButton("Ver red de ejemplo")
        demo.setObjectName("AccentButton")
        demo.clicked.connect(self.demo_requested)
        eb.addWidget(msg)
        eb.addWidget(demo, 0, Qt.AlignmentFlag.AlignCenter)
        eb.addStretch(1)
        lay.addWidget(self.empty, 1)

        self.btn_audit.clicked.connect(self.audit_requested)
        self.btn_cancel.clicked.connect(self.cancel_requested)
        self.table.currentCellChanged.connect(lambda row, *_: self._show_detail(row))
        self.set_targets([])

    # --------------------------------------------------------------- datos
    def set_targets(self, targets: list[WebTarget]) -> None:
        self.targets = list(targets)
        self.results = {}
        self.notice.setText(
            f"{len(targets)} servicio(s) web encontrados. La auditoría hace una visita a la página "
            "principal de cada uno y revisa su cifrado: no prueba contraseñas ni ataca nada." if targets else "")
        self._render()

    def set_results(self, results: list[WebResult]) -> None:
        self.results = {r.target: r for r in results}
        example = any(r.example for r in results)
        reached = sum(1 for r in results if r.reachable)
        issues = sum(len(r.findings) for r in results)
        if example:
            self.notice.setText("Resultados de EJEMPLO: la red de demostración es ficticia, así que no se "
                                "conectó a ningún equipo.")
        elif results:
            self.notice.setText(f"Auditoría terminada: {reached} de {len(results)} servicios respondieron · "
                                f"{issues} hallazgo(s).")
        self._render()

    def set_running(self, running: bool) -> None:
        self.btn_audit.setEnabled(not running and bool(self.targets))
        self.btn_cancel.setVisible(running)
        self.progress.setVisible(running)
        if running:
            self.progress.setRange(0, 0)

    def set_progress(self, done: int, total: int) -> None:
        self.progress.setRange(0, max(total, 1))
        self.progress.setValue(done)
        self.notice.setText(f"Auditando… {done} de {total} servicios.")

    def apply_theme(self, theme: str) -> None:
        self.theme = theme
        self._render()

    # ------------------------------------------------------------- tabla
    def _render(self) -> None:
        has = bool(self.targets)
        self.split.setVisible(has)
        self.empty.setVisible(not has)
        self.btn_audit.setEnabled(has)
        c = THEMES[self.theme]
        self.table.setRowCount(len(self.targets))
        for row, t in enumerate(self.targets):
            r = self.results.get(t)
            cells = [t.url, t.name or t.host] + self._summary(t, r)
            for col, text in enumerate(cells):
                item = QTableWidgetItem(text)
                item.setData(Qt.ItemDataRole.UserRole, t)
                if col == 6 and r and r.findings:
                    item.setForeground(QBrush(QColor(c[RISK_COLOR_KEY[r.worst]])))
                self.table.setItem(row, col, item)
        self.table.resizeColumnsToContents()
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        if has and self.table.currentRow() < 0:
            self.table.setCurrentCell(0, 0)
        self._show_detail(self.table.currentRow())

    @staticmethod
    def _summary(t: WebTarget, r: WebResult | None) -> list[str]:
        if r is None:
            return ["—", "—", "—", "—", "Sin revisar"]
        if not r.reachable:
            return ["—", "—", "—", "—", "No respondió"]
        tls = r.tls
        cipher = tls.version.replace("TLSv", "TLS ") if tls and tls.version else ("Sin cifrar" if not t.tls else "—")
        if tls and tls.days_left is not None:
            cert = "Caducado" if tls.days_left < 0 else f"{tls.days_left} días"
            if tls.self_signed:
                cert += " · autofirmado"
        else:
            cert = "—"
        https = "Sí" if t.tls else ("Redirige" if r.redirects_to_https else "No")
        headers = f"{len(r.headers_present)} de {len(r.headers_present) + len(r.headers_missing)}"
        found = f"{len(r.findings)} · {SEVERITY_LABELS[r.worst].lower()}" if r.findings else "Ninguno"
        return [cipher, cert, https, headers, found]

    def _show_detail(self, row: int) -> None:
        if row < 0 or row >= len(self.targets):
            self.detail.setText("Selecciona un servicio para ver el detalle.")
            return
        t = self.targets[row]
        r = self.results.get(t)
        c = THEMES[self.theme]
        ok, bad, muted = c["accent"], c["danger"], c["muted"]
        e = html.escape
        parts = [f"<b style='font-size:15px'>{e(t.url)}</b>"]
        if r is None:
            parts.append(f"<br><span style='color:{muted}'>Aún sin revisar. Pulsa «Auditar servicios web».</span>")
            self.detail.setText("".join(parts))
            return
        if not r.reachable:
            err = (r.tls.error if r.tls and r.tls.error else r.http.error) or "sin respuesta"
            parts.append(f"<br><span style='color:{muted}'>No se pudo revisar: {e(err)}</span>")
            self.detail.setText("".join(parts))
            return

        def check(good: bool, text: str) -> str:
            mark, color = ("✓", ok) if good else ("✗", bad)
            return f"<br><span style='color:{color}'><b>{mark}</b></span> {e(text)}"

        if r.tls and r.tls.version:
            tls = r.tls
            parts.append(check(tls.version in ("TLSv1.2", "TLSv1.3"), f"Cifrado: {tls.version} · {tls.cipher}"))
            if tls.legacy_checked:
                parts.append(check(not tls.legacy, "Rechaza TLS 1.0 y 1.1" if not tls.legacy
                                   else f"Acepta {' y '.join(tls.legacy)}"))
            if tls.days_left is not None:
                parts.append(check(tls.days_left >= 30, f"Certificado válido {tls.days_left} días más"
                                   if tls.days_left >= 0 else "Certificado caducado"))
            parts.append(check(not tls.self_signed, f"Emitido por: {tls.issuer or '—'}"))
            if tls.key_bits:
                parts.append(check(tls.key_bits >= 2048 or tls.key_bits <= 521,
                                   f"Clave de {tls.key_bits} bits · firma {tls.signature.upper()}"))
        elif not t.tls:
            parts.append(check(r.redirects_to_https, "Redirige a HTTPS" if r.redirects_to_https
                               else "Sin cifrar y sin redirección a HTTPS"))
        if r.http.status is not None:
            parts.append(f"<br><span style='color:{muted}'>Respuesta HTTP {r.http.status}"
                         + (f" · Server: {e(r.http.server)}" if r.http.server else "") + "</span>")
            for key, label in SECURITY_HEADERS.items():
                if key == "strict-transport-security" and not t.tls:
                    continue
                parts.append(check(key in r.http.headers, label))
        if r.findings:
            parts.append("<br><br><b>Qué hacer</b>")
            for f in r.findings:
                color = c[RISK_COLOR_KEY[f.severity]]
                parts.append(f"<br><span style='color:{color}'><b>{f.severity_label}</b></span> · "
                             f"<b>{e(f.title)}</b> — {e(f.recommendation)}")
        self.detail.setText("".join(parts))
