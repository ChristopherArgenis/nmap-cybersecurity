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
from .core.osi import suggested_options
from .pages.history_page import HistoryPage
from .pages.osi_page import OsiPage
from .pages.results_page import ResultsPage
from .pages.scan_page import ScanPage
from .pages.settings_page import SettingsPage
from .pages.topology_page import TopologyPage
from .theme import color, stylesheet
from .widgets import ToggleSwitch

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

        self._build()
        self._connect()
        self.apply_theme(self.theme)
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
        self.history_page = HistoryPage(self.history)
        self.settings_page = SettingsPage()
        self.pages = {
            "scan": self.scan_page,
            "results": self.results_page,
            "topology": self.topology_page,
            "osi": self.osi_page,
            "history": self.history_page,
            "settings": self.settings_page,
        }
        for p in self.pages.values():
            self.stack.addWidget(p)
        h.addWidget(self.stack, 1)
        self.setCentralWidget(root)

        self.settings_page.nmap_path.setText(self.settings.value("nmap_path", "", str))
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
        self.history_page.btn_rerun.setIcon(icon("repeat", color(theme, "text"), 16))
        self.history_page.btn_delete.setIcon(icon("trash", color(theme, "danger"), 16))
        for sw in self.findChildren(ToggleSwitch):
            sw.set_colors(accent, color(theme, "border"), color(theme, "text"), muted)
        self.results_page.apply_theme(theme)
        self.topology_page.apply_theme(theme)
        self.osi_page.apply_theme(theme)
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
        self.show_result(result, xml)
        open_ports = sum(len(h.open_ports) for h in result.hosts) if result else 0
        if self._current:
            self.history.add(
                started_at=self._current["started_at"], targets=self._current["targets"],
                command=self._current["command"], exit_code=code, duration=elapsed,
                hosts_up=result.hosts_up if result else 0, open_ports=open_ports, output=full_text, xml=xml,
            )
            self.history_page.reload()
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
    def show_result(self, result: ScanResult | None, xml: str) -> None:
        """Muestra un resultado en Resultados, Topología y Modelo OSI."""
        self.results_page.set_result(result, exportable=True)
        self.analysis = analyze_scan(result, xml)
        self.topology_page.set_analysis(self.analysis)
        self.osi_page.set_analysis(self.analysis)

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
        self.show_result(result, rec.xml)
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
        self.history_page.reload()

    def _clear_history(self) -> None:
        if QMessageBox.question(self, "Vaciar historial", "¿Eliminar todos los escaneos guardados?") \
                == QMessageBox.StandardButton.Yes:
            self.history.clear()
            self.history_page.reload()

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
        if self.runner.running:
            if QMessageBox.question(self, "Salir", "Hay un escaneo en curso. ¿Detenerlo y salir?") \
                    != QMessageBox.StandardButton.Yes:
                event.ignore()
                return
            self.runner.cancel()
        self.history.close()
        super().closeEvent(event)
