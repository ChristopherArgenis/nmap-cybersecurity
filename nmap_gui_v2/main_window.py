"""Ventana principal de la versión moderna: barra lateral + páginas."""

from __future__ import annotations

import shlex
import time
from pathlib import Path

from PySide6.QtCore import QSettings, QSize, QStandardPaths, Qt
from PySide6.QtGui import QShortcut, QKeySequence
from PySide6.QtWidgets import (
    QApplication,
    QButtonGroup,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

from nmap_gui.core import exporter
from nmap_gui.core.command_builder import needs_privileges
from nmap_gui.core.history import History
from nmap_gui.core.parser import ScanResult, parse_xml
from nmap_gui.core.scanner import ScanRunner, find_nmap, is_admin

from . import __version__
from .icons import icon
from .core.analysis import Analysis, analyze_scan
from .core.changes import compare
from .core.osi import suggested_options
from .core.report import MAP_IMAGE, ReportMeta, build_report_html
from .core.webaudit import web_targets
from .core.webaudit_demo import demo_results
from .pages.changes_page import ChangesPage
from .pages.web_page import WebAuditPage
from .report_pdf import write_pdf
from .web_runner import WebAuditRunner
from .pages.history_page import HistoryPage
from .pages.osi_page import OsiPage
from .pages.results_page import ResultsPage
from .pages.scan_page import ScanPage
from .pages.settings_page import SettingsPage
from .pages.topology_page import TopologyPage
from .theme import color, stylesheet
from .widgets import ToggleSwitch

DEMO_XML = Path(__file__).parent / "data" / "red_ejemplo.xml"
DEMO_PREVIOUS_XML = Path(__file__).parent / "data" / "red_ejemplo_anterior.xml"

DISCLAIMER = (
    "NMAP Studio ejecuta nmap, un escáner de redes.\n\n"
    "Escanear redes o equipos sin autorización puede ser ilegal y violar las políticas "
    "de tu escuela, trabajo o proveedor de internet.\n\n"
    "Úsala solo en redes propias o donde tengas permiso explícito."
)

NAV = [
    ("scan", "Escanear", "radar"),
    ("results", "Resultados", "results"),
    ("topology", "Topología", "topology"),
    ("osi", "Modelo OSI", "layers"),
    ("changes", "Cambios", "diff"),
    ("web", "Auditoría web", "web"),
    ("history", "Historial", "history"),
    ("settings", "Ajustes", "settings"),
]


class ModernWindow(QMainWindow):
    def __init__(self, history_path: str | Path | None = None, settings: QSettings | None = None):
        super().__init__()
        self.setWindowTitle("NMAP Studio")
        self.resize(1280, 820)
        self.setMinimumSize(1000, 680)
        self.settings = settings or QSettings("nmap-cybersecurity", "nmap-studio")
        self.theme = self.settings.value("theme", "oscuro", str)

        if history_path is None:
            data = Path(QStandardPaths.writableLocation(QStandardPaths.StandardLocation.AppDataLocation))
            history_path = data / "historial_v2.sqlite3"
        self.history = History(history_path)
        self.runner = ScanRunner(self)
        self._current: dict = {}
        self._last: dict = {}
        self.analysis = Analysis()
        self.web_runner = WebAuditRunner(self)
        self.web_results: list = []
        self._analysis_args: tuple = (None, "")
        self._demo = False

        self._build()
        self._connect()
        self.apply_theme(self.theme)
        self.changes_page.set_history(self.history.list())
        self.go("scan")

    # ------------------------------------------------------------------ UI
    def _build(self) -> None:
        root = QWidget()
        root.setObjectName("Root")
        h = QHBoxLayout(root)
        h.setContentsMargins(0, 0, 0, 0)
        h.setSpacing(0)

        side = QFrame()
        side.setObjectName("Sidebar")
        side.setFixedWidth(220)
        sv = QVBoxLayout(side)
        sv.setContentsMargins(14, 20, 14, 16)
        sv.setSpacing(4)
        brand_row = QHBoxLayout()
        self.logo = QLabel()
        brand_row.addWidget(self.logo)
        names = QVBoxLayout()
        names.setSpacing(0)
        b = QLabel("NMAP Studio")
        b.setObjectName("Brand")
        s = QLabel("Escáner de red visual")
        s.setObjectName("BrandSub")
        names.addWidget(b)
        names.addWidget(s)
        brand_row.addLayout(names, 1)
        sv.addLayout(brand_row)
        sv.addSpacing(22)

        self.nav_group = QButtonGroup(self)
        self.nav: dict[str, QPushButton] = {}
        for key, text, _ic in NAV:
            btn = QPushButton(f"  {text}")
            btn.setObjectName("NavButton")
            btn.setCheckable(True)
            btn.setIconSize(QSize(18, 18))
            btn.setCursor(Qt.CursorShape.PointingHandCursor)
            self.nav_group.addButton(btn)
            self.nav[key] = btn
            sv.addWidget(btn)
        sv.addStretch(1)
        self.btn_report = QPushButton("  Reporte PDF")
        self.btn_report.setObjectName("AccentButton")
        self.btn_report.setIconSize(QSize(16, 16))
        self.btn_report.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_report.setToolTip("Genera un informe con resumen, mapa, hallazgos y cambios (Ctrl+P)")
        sv.addWidget(self.btn_report)
        sv.addSpacing(10)
        self.side_status = QLabel()
        self.side_status.setObjectName("SidebarFoot")
        self.side_status.setWordWrap(True)
        sv.addWidget(self.side_status)
        h.addWidget(side)

        self.stack = QStackedWidget()
        self.scan_page = ScanPage()
        self.results_page = ResultsPage(self.theme)
        self.topology_page = TopologyPage(self.theme)
        self.osi_page = OsiPage(self.theme)
        self.changes_page = ChangesPage(self.theme)
        self.web_page = WebAuditPage(self.theme)
        self.history_page = HistoryPage(self.history)
        self.settings_page = SettingsPage()
        self.pages = {
            "scan": self.scan_page,
            "results": self.results_page,
            "topology": self.topology_page,
            "osi": self.osi_page,
            "changes": self.changes_page,
            "web": self.web_page,
            "history": self.history_page,
            "settings": self.settings_page,
        }
        for p in self.pages.values():
            self.stack.addWidget(p)
        h.addWidget(self.stack, 1)
        self.setCentralWidget(root)

        self.settings_page.nmap_path.setText(self.settings.value("nmap_path", "", str))
        self.settings_page.author.setText(self.settings.value("report_author", "", str))
        self.settings_page.about.setText(f"NMAP Studio {__version__} · interfaz moderna para nmap")
        self._refresh_nmap_status()

    def _connect(self) -> None:
        self.nav_group.buttonToggled.connect(self._recolor_nav)
        for key, btn in self.nav.items():
            btn.clicked.connect(lambda _=False, k=key: self.go(k))
        sp = self.scan_page
        sp.scan_requested.connect(self.start_scan)
        sp.cancel_requested.connect(self.runner.cancel)
        self.runner.output.connect(sp.append)
        self.runner.progress.connect(sp.set_progress)
        self.runner.finished.connect(self._on_finished)
        self.runner.failed.connect(self._on_failed)

        self.results_page.export_requested.connect(self.export)
        self.results_page.import_requested.connect(self.import_xml)
        hp = self.history_page
        hp.open_requested.connect(self.open_record)
        hp.rerun_requested.connect(self.rerun_record)
        hp.delete_requested.connect(self._delete_record)
        hp.clear_requested.connect(self._clear_history)

        st = self.settings_page
        st.theme_changed.connect(self.apply_theme)
        st.browse_requested.connect(self._browse_nmap)
        st.nmap_path_changed.connect(self._set_nmap_path)

        QShortcut(QKeySequence("Ctrl+1"), self, lambda: self.go("scan"))
        QShortcut(QKeySequence("Ctrl+2"), self, lambda: self.go("results"))
        QShortcut(QKeySequence("Ctrl+3"), self, lambda: self.go("topology"))
        QShortcut(QKeySequence("Ctrl+4"), self, lambda: self.go("osi"))
        QShortcut(QKeySequence("Ctrl+5"), self, lambda: self.go("history"))

        self.topology_page.scan_host.connect(self._scan_host)
        self.topology_page.show_osi.connect(self._osi_for_host)
        self.osi_page.investigate.connect(self._investigate_layer)
        for page in (self.results_page, self.topology_page, self.osi_page, self.changes_page,
                     self.web_page, self.settings_page):
            page.demo_requested.connect(self.load_demo)
        self.changes_page.compare_requested.connect(self.compare_records)
        self.web_page.audit_requested.connect(self.start_web_audit)
        self.btn_report.clicked.connect(lambda: self.generate_report())
        QShortcut(QKeySequence("Ctrl+P"), self, lambda: self.generate_report())
        self.settings_page.author_changed.connect(lambda name: self.settings.setValue("report_author", name))
        self.web_page.cancel_requested.connect(self.web_runner.cancel)
        self.web_runner.progress.connect(self.web_page.set_progress)
        self.web_runner.finished.connect(self._on_web_finished)
        QShortcut(QKeySequence("Ctrl+E"), self, self.export)

    def go(self, key: str) -> None:
        self.nav[key].setChecked(True)
        self.stack.setCurrentWidget(self.pages[key])

    def apply_theme(self, theme: str) -> None:
        self.theme = theme
        self.settings.setValue("theme", theme)
        app = QApplication.instance()
        app.setStyleSheet(stylesheet(theme))
        muted, accent = color(theme, "muted"), color(theme, "accent")
        self._recolor_nav()
        self.logo.setPixmap(icon("shield", accent, 30).pixmap(30, 30))
        self.scan_page.btn_scan.setIcon(icon("play", color(theme, "accent_text"), 14))
        self.scan_page.btn_cancel.setIcon(icon("stop", color(theme, "danger"), 14))
        self.results_page.btn_export.setIcon(icon("export", color(theme, "text"), 16))
        self.results_page.btn_import.setIcon(icon("open", color(theme, "text"), 16))
        self.btn_report.setIcon(icon("report", color(theme, "accent_text"), 16))
        self.history_page.btn_rerun.setIcon(icon("repeat", color(theme, "text"), 16))
        self.history_page.btn_delete.setIcon(icon("trash", color(theme, "danger"), 16))
        for sw in self.findChildren(ToggleSwitch):
            sw.set_colors(accent, color(theme, "border"), color(theme, "text"), muted)
        self.results_page.apply_theme(theme)
        self.topology_page.apply_theme(theme)
        self.osi_page.apply_theme(theme)
        self.changes_page.apply_theme(theme)
        self.web_page.apply_theme(theme)
        st = self.settings_page.dark
        st.blockSignals(True)
        st.setChecked(theme == "oscuro")
        st.blockSignals(False)

    def _recolor_nav(self, *_args) -> None:
        muted, accent = color(self.theme, "muted"), color(self.theme, "accent")
        for key, _text, ic in NAV:
            btn = self.nav[key]
            btn.setIcon(icon(ic, accent if btn.isChecked() else muted))

    # ------------------------------------------------------------- nmap
    def nmap_path(self) -> str | None:
        return find_nmap(self.settings.value("nmap_path", "", str))

    def _refresh_nmap_status(self) -> None:
        path = self.nmap_path()
        if path:
            self.settings_page.nmap_status.setText(f"✔  nmap encontrado en: {path}")
            self.side_status.setText("● nmap listo")
        else:
            self.settings_page.nmap_status.setText("✖  No se encontró nmap. Instálalo o indica su ruta.")
            self.side_status.setText("● nmap no encontrado")

    def _set_nmap_path(self, path: str) -> None:
        self.settings.setValue("nmap_path", path)
        self._refresh_nmap_status()

    def _browse_nmap(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Selecciona el ejecutable de nmap", self.nmap_path() or "")
        if path:
            self.settings_page.nmap_path.setText(path)
            self._set_nmap_path(path)

    # ----------------------------------------------------------- escaneo
    def start_scan(self, args: list[str], targets: str) -> None:
        if self.runner.running:
            return
        nmap = self.nmap_path()
        if not nmap:
            QMessageBox.critical(
                self, "nmap no encontrado",
                "No se encontró nmap en este equipo.\n\nInstálalo desde https://nmap.org/download.html "
                "o indica su ruta en Ajustes.",
            )
            self.go("settings")
            return
        if needs_privileges(args) and not is_admin():
            answer = QMessageBox.question(
                self, "Permisos de administrador",
                "Las opciones elegidas (SYN, UDP, detección de SO…) suelen requerir ejecutar la app "
                "como administrador. Sin permisos, nmap puede fallar.\n\n¿Continuar de todos modos?",
            )
            if answer != QMessageBox.StandardButton.Yes:
                return
        command = " ".join(shlex.quote(a) for a in ["nmap", *args])
        self._current = {"started_at": time.time(), "targets": targets, "command": command}
        self.scan_page.set_running(True, command)
        self.side_status.setText("● Escaneando…")
        self.go("scan")
        self.runner.start(nmap, args)

    def _on_failed(self, message: str) -> None:
        self.scan_page.set_running(False)
        self.scan_page.finish("Error")
        self.scan_page.append(f"\n[Error] {message}\n")
        self._refresh_nmap_status()
        QMessageBox.critical(self, "Error", message)

    def _on_finished(self, result: ScanResult | None, code: int, text: str, xml: str, elapsed: float) -> None:
        sp = self.scan_page
        sp.set_running(False)
        self._refresh_nmap_status()
        full_text = f"$ {self._current.get('command', '')}\n\n{text}"
        self._last = {"result": result, "text": full_text, "xml": xml}
        prev = self._previous_record(self._current.get("targets", ""))
        self.show_result(result, xml, *self._prev_args(prev), "Este escaneo")
        open_ports = sum(len(h.open_ports) for h in result.hosts) if result else 0
        if self._current:
            self.history.add(
                started_at=self._current["started_at"], targets=self._current["targets"],
                command=self._current["command"], exit_code=code, duration=elapsed,
                hosts_up=result.hosts_up if result else 0, open_ports=open_ports, output=full_text, xml=xml,
            )
            self._reload_history()
            if not self.analysis.changes.empty:
                n = len(self.analysis.changes.changes)
                self.side_status.setText(f"● {n} cambio{'s' if n != 1 else ''} desde el escaneo anterior")
        if code == -1:
            sp.finish("Cancelado")
        elif code != 0:
            sp.finish(f"Terminó con código {code}")
            if "root privileges" in text or "requires root" in text:
                QMessageBox.warning(
                    self, "Se necesitan permisos",
                    "Este tipo de escaneo requiere permisos de administrador.\nAbre la app como "
                    "administrador o usa la técnica TCP Connect (-sT).",
                )
        else:
            sp.finish(f"Listo en {elapsed:.1f} s · {open_ports} puertos abiertos")
            if result and result.hosts:
                self.go("results")

    # --------------------------------------------- topología y modelo OSI
    def show_result(
        self,
        result: ScanResult | None,
        xml: str,
        previous: ScanResult | None = None,
        previous_label: str = "Escaneo anterior",
        current_label: str = "Escaneo actual",
    ) -> None:
        """Muestra un resultado en Resultados, Topología, Modelo OSI y Cambios."""
        self.results_page.set_result(result, exportable=True)
        self._analysis_args = (result, xml, previous, previous_label, current_label)
        self._demo = False
        self.web_results = []
        self.web_runner.cancel()
        self.analysis = analyze_scan(*self._analysis_args)
        self.topology_page.set_analysis(self.analysis)
        self.osi_page.set_analysis(self.analysis)
        self.changes_page.set_changes(self.analysis.changes)
        self.web_page.set_targets(web_targets(result, self.analysis.extras))

    # ------------------------------------------------------------- reporte
    def generate_report(self, path: str | None = None) -> str | None:
        """Crea el reporte PDF del análisis actual. Sin `path`, pregunta dónde guardarlo."""
        a = self.analysis
        if a.result is None:
            QMessageBox.information(self, "Reporte PDF",
                                    "Primero ejecuta un escaneo, abre uno del historial o carga la red de ejemplo.")
            return None
        if path is None:
            default = time.strftime("informe-red-%Y-%m-%d.pdf")
            path, _ = QFileDialog.getSaveFileName(self, "Guardar reporte PDF", default, "PDF (*.pdf)")
            if not path:
                return None
            if not path.lower().endswith(".pdf"):
                path += ".pdf"
        author = self.settings.value("report_author", "", str)
        meta = ReportMeta(
            author=author,
            scope=self._current.get("targets", "") or a.topology.subnet,
            command=a.result.command,
            generated_at=time.time(),
            demo=self._demo,
            app_version=__version__,
        )
        images = {}
        snap = self.topology_page.snapshot("claro")
        if snap is not None:
            images[MAP_IMAGE] = snap
        else:
            meta.include_map = False
        try:
            write_pdf(build_report_html(a, self.web_results, meta), path, images, meta.title, author)
        except OSError as exc:
            QMessageBox.critical(self, "No se pudo guardar", str(exc))
            return None
        self.side_status.setText(f"● Reporte guardado: {Path(path).name}")
        return path

    # ------------------------------------------------------- auditoría web
    def start_web_audit(self) -> None:
        targets = self.web_page.targets
        if not targets or self.web_runner.running:
            return
        if self._demo:
            # La red de ejemplo es ficticia: nunca se conecta a esas direcciones.
            self._on_web_finished(demo_results(targets))
            return
        hosts = sorted({t.host for t in targets})
        shown = ", ".join(hosts[:6]) + (" …" if len(hosts) > 6 else "")
        answer = QMessageBox.question(
            self, "Auditoría web",
            f"Se visitará la página principal de {len(targets)} servicio(s) web en {len(hosts)} equipo(s):\n"
            f"{shown}\n\nNo se prueban contraseñas ni se ataca nada, pero sí se conecta a esos equipos.\n"
            "Continúa solo si son tuyos o tienes permiso.\n\n¿Continuar?")
        if answer != QMessageBox.StandardButton.Yes:
            return
        self.web_page.set_running(True)
        self.side_status.setText("● Auditoría web en curso…")
        self.web_runner.start(targets)

    def _on_web_finished(self, results: list) -> None:
        self.web_page.set_running(False)
        self.web_results = results
        self.web_page.set_results(results)
        extra = [f for r in results for f in r.findings]
        result, xml, *rest = self._analysis_args
        demo = self._demo
        self.analysis = analyze_scan(result, xml, *rest, extra_findings=extra)
        self._demo = demo
        self.topology_page.set_analysis(self.analysis)
        self.osi_page.set_analysis(self.analysis)
        self.side_status.setText(f"● Auditoría web: {len(extra)} hallazgo(s)")

    # ------------------------------------------------- vigilancia de cambios
    def _previous_record(self, targets: str, before: float | None = None):
        """El escaneo más reciente de los mismos objetivos (anterior a `before`)."""
        if not targets:
            return None
        for rec in self.history.list():
            if rec.targets == targets and (before is None or rec.started_at < before):
                return self.history.get(rec.id)
        return None

    @staticmethod
    def _parse(xml: str) -> ScanResult | None:
        try:
            return parse_xml(xml) if xml.strip() else None
        except ValueError:
            return None

    def _prev_args(self, rec) -> tuple:
        if rec is None:
            return (None, "Escaneo anterior")
        return (self._parse(rec.xml), f"Escaneo del {rec.started_text}")

    def compare_records(self, before_id: int, after_id: int) -> None:
        a, b = self.history.get(before_id), self.history.get(after_id)
        if a is None or b is None:
            return
        if a.started_at > b.started_at:
            a, b = b, a
        cs = compare(self._parse(a.xml), self._parse(b.xml),
                     f"{a.started_text} · {a.targets}", f"{b.started_text} · {b.targets}")
        self.changes_page.set_changes(cs)

    def _reload_history(self) -> None:
        self.history_page.reload()
        self.changes_page.set_history(self.history.list())

    def load_demo(self) -> None:
        """Carga la red de ejemplo incluida en la app (datos ficticios, no escanea nada)."""
        xml = DEMO_XML.read_text(encoding="utf-8")
        result = parse_xml(xml)
        text = ("[Red de ejemplo: datos ficticios incluidos en la app. "
                "No se ejecutó nmap ni se escaneó ninguna red.]\n")
        self._last = {"result": result, "text": text, "xml": xml}
        self._current = {"targets": "192.168.1.0/24"}
        previous = parse_xml(DEMO_PREVIOUS_XML.read_text(encoding="utf-8"))
        self.show_result(result, xml, previous, "Red de ejemplo · hace una semana", "Red de ejemplo · hoy")
        self._demo = True
        self.scan_page.console.setPlainText(text)
        self.side_status.setText("● Viendo la red de ejemplo")
        self.go("topology")

    def _scan_host(self, ip: str) -> None:
        self.scan_page.target.setText(ip)
        self.scan_page.select_profile("Puertos y servicios")
        self.go("scan")

    def _osi_for_host(self, ip: str) -> None:
        self.osi_page.focus_host(ip)
        self.go("osi")

    def _investigate_layer(self, layer: int, host: str) -> None:
        targets = host or self._current.get("targets", "") or self.analysis.topology.subnet
        self.scan_page.target.setText(targets)
        self.scan_page.set_options(suggested_options(layer, targets))
        self.scan_page.select_profile("Personalizado")
        self.go("scan")

    # ---------------------------------------------------------- historial
    def open_record(self, scan_id: int) -> None:
        rec = self.history.get(scan_id)
        if rec is None:
            return
        result = None
        if rec.xml.strip():
            try:
                result = parse_xml(rec.xml)
            except ValueError:
                result = None
        self._last = {"result": result, "text": rec.output, "xml": rec.xml}
        prev = self._previous_record(rec.targets, before=rec.started_at)
        self.show_result(result, rec.xml, *self._prev_args(prev), f"Escaneo del {rec.started_text}")
        self.scan_page.console.setPlainText(rec.output)
        self.go("results")

    def rerun_record(self, scan_id: int) -> None:
        rec = self.history.get(scan_id)
        if rec is None or self.runner.running:
            return
        answer = QMessageBox.question(self, "Repetir escaneo", f"¿Ejecutar de nuevo este comando?\n\n{rec.command}")
        if answer == QMessageBox.StandardButton.Yes:
            self.scan_page.target.setText(rec.targets)
            self.start_scan(shlex.split(rec.command)[1:], rec.targets)

    def _delete_record(self, scan_id: int) -> None:
        self.history.delete(scan_id)
        self._reload_history()

    def _clear_history(self) -> None:
        if QMessageBox.question(self, "Vaciar historial", "¿Eliminar todos los escaneos guardados?") \
                == QMessageBox.StandardButton.Yes:
            self.history.clear()
            self._reload_history()

    # --------------------------------------------------- importar/exportar
    def import_xml(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Abrir XML de nmap", "", "XML de nmap (*.xml)")
        if path:
            self.load_xml_file(path)

    def load_xml_file(self, path: str) -> None:
        try:
            xml = Path(path).read_text(encoding="utf-8", errors="replace")
            result = parse_xml(xml)
        except (OSError, ValueError) as exc:
            QMessageBox.critical(self, "No se pudo abrir", str(exc))
            return
        self._last = {"result": result, "text": f"[Importado de {path}]\n", "xml": xml}
        self._current = {"targets": " ".join(h.address for h in result.hosts if h.status == "up")}
        self.show_result(result, xml)
        self.go("results")

    def export(self) -> None:
        if not self._last:
            return
        filters = ";;".join(exporter.FORMATS.values())
        path, chosen = QFileDialog.getSaveFileName(self, "Exportar resultados", "escaneo.html", filters)
        if not path:
            return
        fmt = next((k for k, v in exporter.FORMATS.items() if v == chosen), Path(path).suffix.lstrip(".") or "txt")
        if not Path(path).suffix:
            path += f".{fmt}"
        try:
            exporter.export(path, fmt, result=self._last["result"], text_output=self._last["text"],
                            xml=self._last["xml"])
        except (OSError, ValueError) as exc:
            QMessageBox.critical(self, "No se pudo exportar", str(exc))
            return
        self.side_status.setText(f"● Exportado: {Path(path).name}")

    # ---------------------------------------------------------- ciclo vida
    def show_disclaimer_once(self) -> bool:
        if self.settings.value("disclaimer_accepted", False, bool):
            return True
        box = QMessageBox(self)
        box.setWindowTitle("Uso responsable")
        box.setIcon(QMessageBox.Icon.Warning)
        box.setText(DISCLAIMER)
        accept = box.addButton("Entiendo y acepto", QMessageBox.ButtonRole.AcceptRole)
        box.addButton("Salir", QMessageBox.ButtonRole.RejectRole)
        box.exec()
        if box.clickedButton() is accept:
            self.settings.setValue("disclaimer_accepted", True)
            return True
        return False

    def closeEvent(self, event) -> None:  # noqa: N802
        self.web_runner.cancel()
        if self.runner.running:
            if QMessageBox.question(self, "Salir", "Hay un escaneo en curso. ¿Detenerlo y salir?") \
                    != QMessageBox.StandardButton.Yes:
                event.ignore()
                return
            self.runner.cancel()
        self.history.close()
        super().closeEvent(event)
