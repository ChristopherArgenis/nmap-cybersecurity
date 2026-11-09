"""Ventana principal de la aplicación."""

from __future__ import annotations

import shlex
import time
from pathlib import Path

from PySide6.QtCore import QSettings, QStandardPaths, Qt
from PySide6.QtGui import QAction, QFontDatabase, QGuiApplication, QKeySequence, QTextCursor
from PySide6.QtWidgets import (
    QComboBox,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QPlainTextEdit,
    QProgressBar,
    QPushButton,
    QSplitter,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from .. import __version__
from ..core import exporter
from ..core.command_builder import (
    PROFILES,
    ValidationError,
    apply_profile,
    build_args,
    display_command,
    needs_privileges,
)
from ..core.history import History
from ..core.parser import ScanResult, parse_xml
from ..core.scanner import ScanRunner, find_nmap, is_admin
from .builder_panel import BuilderPanel
from .history_view import HistoryView
from .results_view import ResultsView

DISCLAIMER = (
    "Esta herramienta ejecuta nmap, un escáner de redes.\n\n"
    "Escanear redes o equipos sin autorización puede ser ilegal y violar "
    "las políticas de tu escuela, trabajo o proveedor de internet.\n\n"
    "Úsala solo en redes propias o donde tengas permiso explícito por escrito."
)


class MainWindow(QMainWindow):
    def __init__(self, history_path: str | Path | None = None):
        super().__init__()
        self.setWindowTitle("NMAP GUI")
        self.resize(1200, 760)
        self.settings = QSettings("nmap-cybersecurity", "nmap-gui")

        if history_path is None:
            data_dir = Path(QStandardPaths.writableLocation(QStandardPaths.StandardLocation.AppDataLocation))
            history_path = data_dir / "historial.sqlite3"
        self.history = History(history_path)

        self.runner = ScanRunner(self)
        self._current: dict = {}
        self._last: dict = {}

        self._build_ui()
        self._build_menu()
        self._connect()
        self._update_command()

    # ------------------------------------------------------------------ UI
    def _build_ui(self) -> None:
        # Barra superior: objetivo, perfil, botones
        self.target = QLineEdit()
        self.target.setPlaceholderText("Objetivo: 192.168.1.1, 192.168.1.0/24, ejemplo.com …")
        self.profile = QComboBox()
        self.profile.addItems(PROFILES.keys())
        self.btn_scan = QPushButton("Escanear")
        self.btn_scan.setDefault(True)
        self.btn_cancel = QPushButton("Cancelar")
        self.btn_cancel.setEnabled(False)

        top = QHBoxLayout()
        top.addWidget(QLabel("Objetivo:"))
        top.addWidget(self.target, 3)
        top.addWidget(QLabel("Perfil:"))
        top.addWidget(self.profile, 1)
        top.addWidget(self.btn_scan)
        top.addWidget(self.btn_cancel)

        # Vista previa del comando
        self.command = QLineEdit()
        self.command.setReadOnly(True)
        mono = QFontDatabase.systemFont(QFontDatabase.SystemFont.FixedFont)
        self.command.setFont(mono)
        self.btn_copy = QPushButton("Copiar")
        cmd_row = QHBoxLayout()
        cmd_row.addWidget(QLabel("Comando:"))
        cmd_row.addWidget(self.command, 1)
        cmd_row.addWidget(self.btn_copy)

        # Panel de opciones + pestañas
        self.builder = BuilderPanel()
        self.output = QPlainTextEdit()
        self.output.setReadOnly(True)
        self.output.setFont(mono)
        self.output.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        self.results = ResultsView()
        self.history_view = HistoryView(self.history)

        self.tabs = QTabWidget()
        self.tabs.addTab(self.output, "Salida de nmap")
        self.tabs.addTab(self.results, "Hosts y puertos")
        self.tabs.addTab(self.history_view, "Historial")

        split = QSplitter(Qt.Orientation.Horizontal)
        split.addWidget(self.builder)
        split.addWidget(self.tabs)
        split.setStretchFactor(1, 1)
        split.setSizes([360, 840])

        central = QWidget()
        layout = QVBoxLayout(central)
        layout.addLayout(top)
        layout.addLayout(cmd_row)
        layout.addWidget(split, 1)
        self.setCentralWidget(central)

        self.progress = QProgressBar()
        self.progress.setMaximumWidth(220)
        self.progress.setVisible(False)
        self.statusBar().addPermanentWidget(self.progress)
        self.statusBar().showMessage("Listo.")

    def _build_menu(self) -> None:
        m_file = self.menuBar().addMenu("&Archivo")
        self.act_export = QAction("&Exportar resultados…", self, shortcut=QKeySequence("Ctrl+E"))
        self.act_export.setEnabled(False)
        act_import = QAction("&Abrir XML de nmap…", self, shortcut=QKeySequence.StandardKey.Open)
        act_quit = QAction("&Salir", self, shortcut=QKeySequence.StandardKey.Quit)
        m_file.addAction(act_import)
        m_file.addAction(self.act_export)
        m_file.addSeparator()
        m_file.addAction(act_quit)

        m_tools = self.menuBar().addMenu("&Herramientas")
        act_path = QAction("&Ruta de nmap…", self)
        m_tools.addAction(act_path)

        m_help = self.menuBar().addMenu("A&yuda")
        act_legal = QAction("Aviso de &uso responsable", self)
        act_about = QAction("&Acerca de", self)
        m_help.addAction(act_legal)
        m_help.addAction(act_about)

        self.act_export.triggered.connect(self._export)
        act_import.triggered.connect(self._import_xml)
        act_quit.triggered.connect(self.close)
        act_path.triggered.connect(self._choose_nmap)
        act_legal.triggered.connect(lambda: QMessageBox.information(self, "Uso responsable", DISCLAIMER))
        act_about.triggered.connect(self._about)

    def _connect(self) -> None:
        self.target.textChanged.connect(self._update_command)
        self.target.returnPressed.connect(self._start_scan)
        self.builder.changed.connect(self._update_command)
        self.profile.currentTextChanged.connect(self._apply_profile)
        self.btn_scan.clicked.connect(self._start_scan)
        self.btn_cancel.clicked.connect(self.runner.cancel)
        self.btn_copy.clicked.connect(lambda: QGuiApplication.clipboard().setText(self.command.text()))

        self.runner.output.connect(self._append_output)
        self.runner.progress.connect(lambda pct: self.progress.setValue(int(pct)))
        self.runner.finished.connect(self._on_finished)
        self.runner.failed.connect(self._on_failed)

        self.history_view.open_requested.connect(self._open_history)
        self.history_view.rerun_requested.connect(self._rerun_history)

    # ------------------------------------------------------------ Acciones
    def nmap_path(self) -> str | None:
        return find_nmap(self.settings.value("nmap_path", "", str))

    def _apply_profile(self, name: str) -> None:
        if name != "Personalizado":
            self.builder.set_options(apply_profile(name))

    def _update_command(self) -> list[str] | None:
        targets = self.target.text().strip()
        try:
            if not targets:
                # Sin objetivo todavía: vista previa con un marcador.
                preview = build_args(self.builder.options("OBJETIVO"))
                self.command.setText(display_command(preview[:-1]) + " <objetivo>")
                return None
            args = build_args(self.builder.options(targets))
        except ValidationError as exc:
            self.command.setText(f"⚠ {exc}")
            return None
        self.command.setText(display_command(args))
        return args

    def _start_scan(self) -> None:
        if self.runner.running:
            return
        if not self.target.text().strip():
            QMessageBox.warning(self, "Falta el objetivo", "Escribe una IP, rango o dominio a escanear.")
            return
        args = self._update_command()
        if args is None:
            QMessageBox.warning(self, "Revisa los datos", self.command.text().removeprefix("⚠ "))
            return
        self._run(args, self.target.text().strip())

    def _run(self, args: list[str], targets: str) -> None:
        nmap = self.nmap_path()
        if not nmap:
            QMessageBox.critical(
                self,
                "nmap no encontrado",
                "No se encontró nmap en este equipo.\n\n"
                "Instálalo desde https://nmap.org/download.html o indica su ruta en "
                "Herramientas → Ruta de nmap.",
            )
            return
        if needs_privileges(args) and not is_admin():
            answer = QMessageBox.question(
                self,
                "Permisos de administrador",
                "Algunas opciones elegidas (SYN, UDP, detección de SO…) normalmente requieren "
                "ejecutar la aplicación como administrador/root. Sin permisos, nmap puede "
                "fallar o usar un escaneo TCP Connect.\n\n¿Continuar de todos modos?",
            )
            if answer != QMessageBox.StandardButton.Yes:
                return

        self._current = {
            "started_at": time.time(),
            "targets": targets,
            "command": display_command(args),
        }
        self.output.clear()
        self.output.appendPlainText(f"$ {self._current['command']}\n")
        self.results.clear()
        self.tabs.setCurrentWidget(self.output)
        self._set_running(True)
        self.runner.start(nmap, args)

    def _set_running(self, running: bool) -> None:
        self.btn_scan.setEnabled(not running)
        self.btn_cancel.setEnabled(running)
        self.progress.setVisible(running)
        self.progress.setValue(0)
        self.progress.setRange(0, 100)
        self.statusBar().showMessage("Escaneando…" if running else "Listo.")

    def _append_output(self, text: str) -> None:
        self.output.moveCursor(QTextCursor.MoveOperation.End)
        self.output.insertPlainText(text)
        self.output.moveCursor(QTextCursor.MoveOperation.End)

    def _on_failed(self, message: str) -> None:
        self._set_running(False)
        self.output.appendPlainText(f"\n[Error] {message}")
        QMessageBox.critical(self, "Error", message)

    def _on_finished(self, result: ScanResult | None, exit_code: int, text: str, xml: str, elapsed: float) -> None:
        self._set_running(False)
        full_text = f"$ {self._current.get('command', '')}\n\n{text}"
        self._last = {"result": result, "text": full_text, "xml": xml}
        self.act_export.setEnabled(bool(text or xml))
        self.results.set_result(result)

        open_ports = sum(len(h.open_ports) for h in result.hosts) if result else 0
        if self._current:
            self.history.add(
                started_at=self._current["started_at"],
                targets=self._current["targets"],
                command=self._current["command"],
                exit_code=exit_code,
                duration=elapsed,
                hosts_up=result.hosts_up if result else 0,
                open_ports=open_ports,
                output=full_text,
                xml=xml,
            )
            self.history_view.reload()

        if exit_code == -1:
            self.statusBar().showMessage("Escaneo cancelado.")
        elif exit_code != 0:
            self.statusBar().showMessage(f"nmap terminó con código {exit_code}. Revisa la salida.")
            if "root privileges" in text or "requires root" in text:
                QMessageBox.warning(
                    self,
                    "Se necesitan permisos",
                    "nmap indicó que este tipo de escaneo requiere permisos de administrador/root.\n"
                    "Ejecuta la aplicación con sudo (Linux/macOS) o como administrador (Windows), "
                    "o elige el tipo TCP Connect (-sT).",
                )
        else:
            self.statusBar().showMessage(f"Escaneo terminado en {elapsed:.1f} s · {open_ports} puertos abiertos.")
            if result and result.hosts:
                self.tabs.setCurrentWidget(self.results)

    def _show_record(self, scan_id: int) -> None:
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
        self.act_export.setEnabled(True)
        self.output.setPlainText(rec.output)
        self.results.set_result(result)

    def _open_history(self, scan_id: int) -> None:
        self._show_record(scan_id)
        self.tabs.setCurrentWidget(self.results)

    def _rerun_history(self, scan_id: int) -> None:
        rec = self.history.get(scan_id)
        if rec is None or self.runner.running:
            return
        answer = QMessageBox.question(
            self, "Repetir escaneo", f"¿Ejecutar de nuevo este comando?\n\n{rec.command}"
        )
        if answer != QMessageBox.StandardButton.Yes:
            return
        args = shlex.split(rec.command)[1:]  # sin el ejecutable
        self.target.setText(rec.targets)
        self._run(args, rec.targets)

    def _import_xml(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Abrir XML de nmap", "", "XML de nmap (*.xml)")
        if not path:
            return
        try:
            xml = Path(path).read_text(encoding="utf-8", errors="replace")
            result = parse_xml(xml)
        except (OSError, ValueError) as exc:
            QMessageBox.critical(self, "No se pudo abrir", str(exc))
            return
        self._last = {"result": result, "text": f"[Importado de {path}]\n", "xml": xml}
        self.act_export.setEnabled(True)
        self.results.set_result(result)
        self.tabs.setCurrentWidget(self.results)

    def _export(self) -> None:
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
            exporter.export(path, fmt, result=self._last["result"], text_output=self._last["text"], xml=self._last["xml"])
        except (OSError, ValueError) as exc:
            QMessageBox.critical(self, "No se pudo exportar", str(exc))
            return
        self.statusBar().showMessage(f"Exportado a {path}")

    def _choose_nmap(self) -> None:
        current = self.nmap_path() or ""
        path, _ = QFileDialog.getOpenFileName(self, "Selecciona el ejecutable de nmap", current)
        if path:
            self.settings.setValue("nmap_path", path)
            self.statusBar().showMessage(f"Usando nmap en {path}")

    def _about(self) -> None:
        nmap = self.nmap_path() or "no encontrado"
        QMessageBox.about(
            self,
            "Acerca de NMAP GUI",
            f"<b>NMAP GUI {__version__}</b><br>Interfaz gráfica para nmap.<br><br>nmap: {nmap}",
        )

    def show_disclaimer_once(self) -> bool:
        """Muestra el aviso legal la primera vez. Devuelve False si el usuario no acepta."""
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

    def closeEvent(self, event) -> None:
        if self.runner.running:
            answer = QMessageBox.question(self, "Salir", "Hay un escaneo en curso. ¿Cancelarlo y salir?")
            if answer != QMessageBox.StandardButton.Yes:
                event.ignore()
                return
            self.runner.cancel()
        self.history.close()
        super().closeEvent(event)
