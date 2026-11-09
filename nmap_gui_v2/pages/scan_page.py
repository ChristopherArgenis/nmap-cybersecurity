"""Pantalla «Nuevo escaneo»: objetivo, perfiles, opciones, comando y consola en vivo."""

from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QFontDatabase, QGuiApplication, QIntValidator, QTextCursor
from PySide6.QtWidgets import (
    QButtonGroup,
    QComboBox,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QProgressBar,
    QPushButton,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

from nmap_gui.core.command_builder import (
    PROFILES,
    SCAN_TYPES,
    TIMING_LABELS,
    ScanOptions,
    ValidationError,
    apply_profile,
    build_args,
    display_command,
)

from ..widgets import Card, ToggleSwitch

PROFILE_HINTS = {
    "Escaneo rápido": "100 puertos más comunes",
    "Escaneo normal": "1000 puertos, opciones por defecto",
    "Puertos y servicios": "Detecta versiones (-sV)",
    "Escaneo intenso": "SO, versiones, scripts (-A)",
    "Descubrir hosts (ping)": "Quién está conectado (-sn)",
    "Todos los puertos TCP": "65 535 puertos",
    "UDP rápido": "100 puertos UDP (admin)",
    "Personalizado": "Tú eliges las opciones",
}


def page_header(title: str, subtitle: str) -> QWidget:
    w = QWidget()
    v = QVBoxLayout(w)
    v.setContentsMargins(0, 0, 0, 4)
    v.setSpacing(2)
    t = QLabel(title)
    t.setObjectName("PageTitle")
    s = QLabel(subtitle)
    s.setObjectName("PageSubtitle")
    v.addWidget(t)
    v.addWidget(s)
    return w


class ScanPage(QScrollArea):
    scan_requested = Signal(list, str)  # argumentos, objetivos
    cancel_requested = Signal()

    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent)
        self.setWidgetResizable(True)
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        root = QWidget()
        root.setObjectName("Root")
        lay = QVBoxLayout(root)
        lay.setContentsMargins(28, 24, 28, 24)
        lay.setSpacing(16)
        lay.addWidget(page_header("Nuevo escaneo", "Escribe un objetivo, elige un perfil y pulsa Escanear."))

        # --- Objetivo ---
        hero = Card()
        row = QHBoxLayout()
        row.setSpacing(10)
        self.target = QLineEdit()
        self.target.setObjectName("HeroInput")
        self.target.setPlaceholderText("192.168.1.1   ·   192.168.1.0/24   ·   ejemplo.com")
        self.btn_scan = QPushButton("  Escanear")
        self.btn_scan.setObjectName("PrimaryButton")
        self.btn_scan.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_cancel = QPushButton("  Detener")
        self.btn_cancel.setObjectName("DangerButton")
        self.btn_cancel.setVisible(False)
        row.addWidget(self.target, 1)
        row.addWidget(self.btn_scan)
        row.addWidget(self.btn_cancel)
        hero.body.addLayout(row)

        # Perfiles como "chips"
        lbl = QLabel("Perfil de escaneo")
        lbl.setObjectName("Muted")
        hero.body.addWidget(lbl)
        grid = QGridLayout()
        grid.setSpacing(8)
        self.profile_group = QButtonGroup(self)
        self.profile_group.setExclusive(True)
        self.chips: dict[str, QPushButton] = {}
        for i, name in enumerate(PROFILES):
            chip = QPushButton(name)
            chip.setObjectName("Chip")
            chip.setCheckable(True)
            chip.setToolTip(PROFILE_HINTS.get(name, ""))
            chip.setCursor(Qt.CursorShape.PointingHandCursor)
            self.profile_group.addButton(chip)
            self.chips[name] = chip
            grid.addWidget(chip, i // 4, i % 4)
        hero.body.addLayout(grid)
        self.profile_hint = QLabel("")
        self.profile_hint.setObjectName("Muted")
        hero.body.addWidget(self.profile_hint)
        lay.addWidget(hero)

        # --- Opciones avanzadas (plegable) ---
        adv = Card()
        head = QHBoxLayout()
        t = QLabel("Opciones avanzadas")
        t.setObjectName("CardTitle")
        self.btn_toggle_adv = QPushButton("Mostrar")
        self.btn_toggle_adv.setObjectName("LinkButton")
        self.btn_toggle_adv.setCursor(Qt.CursorShape.PointingHandCursor)
        head.addWidget(t)
        head.addStretch(1)
        head.addWidget(self.btn_toggle_adv)
        adv.body.addLayout(head)
        self.adv_body = QWidget()
        self._build_options(self.adv_body)
        self.adv_body.setVisible(False)
        adv.body.addWidget(self.adv_body)
        lay.addWidget(adv)

        # --- Comando ---
        cmd = Card()
        h = QHBoxLayout()
        t = QLabel("Comando que se ejecutará")
        t.setObjectName("CardTitle")
        self.btn_copy = QPushButton("Copiar")
        self.btn_copy.setObjectName("LinkButton")
        self.btn_copy.setCursor(Qt.CursorShape.PointingHandCursor)
        h.addWidget(t)
        h.addStretch(1)
        h.addWidget(self.btn_copy)
        cmd.body.addLayout(h)
        self.command = QLabel()
        self.command.setObjectName("CodeBox")
        self.command.setWordWrap(True)
        self.command.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        cmd.body.addWidget(self.command)
        lay.addWidget(cmd)

        # --- Consola ---
        con = Card()
        h = QHBoxLayout()
        t = QLabel("Salida en vivo")
        t.setObjectName("CardTitle")
        self.status = QLabel("En espera")
        self.status.setObjectName("Muted")
        h.addWidget(t)
        h.addStretch(1)
        h.addWidget(self.status)
        con.body.addLayout(h)
        self.progress = QProgressBar()
        self.progress.setTextVisible(False)
        self.progress.setRange(0, 100)
        self.progress.setValue(0)
        con.body.addWidget(self.progress)
        self.console = QPlainTextEdit()
        self.console.setObjectName("Console")
        self.console.setReadOnly(True)
        self.console.setMinimumHeight(220)
        self.console.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        self.console.setFont(QFontDatabase.systemFont(QFontDatabase.SystemFont.FixedFont))
        self.console.setPlaceholderText("Aquí aparecerá la salida de nmap mientras se ejecuta el escaneo.")
        con.body.addWidget(self.console)
        lay.addWidget(con)
        lay.addStretch(1)
        self.setWidget(root)

        # Señales
        self.target.textChanged.connect(self.update_command)
        self.target.returnPressed.connect(self._request_scan)
        self.btn_scan.clicked.connect(self._request_scan)
        self.btn_cancel.clicked.connect(self.cancel_requested)
        self.btn_copy.clicked.connect(self._copy)
        self.btn_toggle_adv.clicked.connect(self._toggle_adv)
        self.profile_group.buttonClicked.connect(lambda b: self.select_profile(b.text()))
        self.select_profile("Escaneo rápido")

    # ------------------------------------------------------------ opciones
    def _build_options(self, parent: QWidget) -> None:
        g = QGridLayout(parent)
        g.setContentsMargins(0, 4, 0, 0)
        g.setHorizontalSpacing(18)
        g.setVerticalSpacing(10)

        def label(text: str) -> QLabel:
            lbl = QLabel(text)
            lbl.setObjectName("Muted")
            return lbl

        self.scan_type = QComboBox()
        for flag, text in SCAN_TYPES.items():
            self.scan_type.addItem(f"{text}  {flag}".strip(), flag)
        self.timing = QComboBox()
        self.timing.addItem("Predeterminado", None)
        for level, text in TIMING_LABELS.items():
            self.timing.addItem(text, level)
        self.ports = QLineEdit()
        self.ports.setPlaceholderText("22,80,443 o 1-1000")
        self.top_ports = QLineEdit()
        self.top_ports.setPlaceholderText("ej. 100 (vacío = no usar)")
        self.top_ports.setValidator(QIntValidator(1, 65535, self.top_ports))
        self.scripts = QLineEdit()
        self.scripts.setPlaceholderText("http-title,ssl-cert o vuln")
        self.extra_args = QLineEdit()
        self.extra_args.setPlaceholderText("--max-retries 2")

        g.addWidget(label("Técnica"), 0, 0)
        g.addWidget(label("Velocidad"), 0, 1)
        g.addWidget(self.scan_type, 1, 0)
        g.addWidget(self.timing, 1, 1)
        g.addWidget(label("Puertos (-p)"), 2, 0)
        g.addWidget(label("Puertos más comunes"), 2, 1)
        g.addWidget(self.ports, 3, 0)
        g.addWidget(self.top_ports, 3, 1)
        g.addWidget(label("Scripts NSE"), 4, 0)
        g.addWidget(label("Argumentos extra"), 4, 1)
        g.addWidget(self.scripts, 5, 0)
        g.addWidget(self.extra_args, 5, 1)

        self.switches: dict[str, ToggleSwitch] = {}
        specs = [
            ("fast", "Rápido (-F)"),
            ("service_version", "Versiones de servicios (-sV)"),
            ("os_detection", "Sistema operativo (-O)"),
            ("default_scripts", "Scripts por defecto (-sC)"),
            ("aggressive", "Agresivo (-A)"),
            ("skip_ping", "Sin ping (-Pn)"),
            ("no_dns", "Sin DNS (-n)"),
            ("verbose", "Detallado (-v)"),
            ("open_only", "Solo abiertos (--open)"),
            ("ipv6", "IPv6 (-6)"),
        ]
        for i, (key, text) in enumerate(specs):
            sw = ToggleSwitch(text)
            self.switches[key] = sw
            g.addWidget(sw, 6 + i // 2, i % 2)

        self._texts = {"ports": self.ports, "scripts": self.scripts, "extra_args": self.extra_args}
        for sw in self.switches.values():
            sw.toggled.connect(self._on_option_changed)
        for le in self._texts.values():
            le.textChanged.connect(self._on_option_changed)
        self.scan_type.currentIndexChanged.connect(self._on_option_changed)
        self.timing.currentIndexChanged.connect(self._on_option_changed)
        self.top_ports.textChanged.connect(self._on_option_changed)

    def _toggle_adv(self) -> None:
        visible = not self.adv_body.isVisible()
        self.adv_body.setVisible(visible)
        self.btn_toggle_adv.setText("Ocultar" if visible else "Mostrar")

    def options(self, targets: str) -> ScanOptions:
        opts = ScanOptions(targets=targets)
        opts.scan_type = self.scan_type.currentData() or ""
        opts.timing = self.timing.currentData()
        opts.top_ports = int(self.top_ports.text()) if self.top_ports.text().isdigit() else None
        for key, sw in self.switches.items():
            setattr(opts, key, sw.isChecked())
        for key, le in self._texts.items():
            setattr(opts, key, le.text())
        return opts

    def set_options(self, opts: ScanOptions) -> None:
        widgets = [self.scan_type, self.timing, self.top_ports, *self.switches.values(), *self._texts.values()]
        for w in widgets:
            w.blockSignals(True)
        try:
            self.scan_type.setCurrentIndex(max(0, self.scan_type.findData(opts.scan_type)))
            self.timing.setCurrentIndex(max(0, self.timing.findData(opts.timing)) if opts.timing is not None else 0)
            self.top_ports.setText(str(opts.top_ports) if opts.top_ports else "")
            for key, sw in self.switches.items():
                sw.setChecked(getattr(opts, key))
            for key, le in self._texts.items():
                le.setText(getattr(opts, key))
        finally:
            for w in widgets:
                w.blockSignals(False)
        self._sync_enabled()
        self.update_command()

    def select_profile(self, name: str) -> None:
        self.chips[name].setChecked(True)
        self.profile_hint.setText(PROFILE_HINTS.get(name, ""))
        if name == "Personalizado":
            self.adv_body.setVisible(True)
            self.btn_toggle_adv.setText("Ocultar")
            self.update_command()
        else:
            self.set_options(apply_profile(name))

    def _on_option_changed(self) -> None:
        # Tocar una opción convierte el perfil en «Personalizado».
        custom = self.chips["Personalizado"]
        if not custom.isChecked():
            custom.setChecked(True)
            self.profile_hint.setText(PROFILE_HINTS["Personalizado"])
        self._sync_enabled()
        self.update_command()

    def _sync_enabled(self) -> None:
        port_scan = self.scan_type.currentData() != "-sn"
        aggressive = self.switches["aggressive"].isChecked()
        for w in (self.ports, self.top_ports, self.switches["fast"]):
            w.setEnabled(port_scan)
        self.switches["service_version"].setEnabled(port_scan and not aggressive)
        self.switches["os_detection"].setEnabled(not aggressive)
        self.switches["default_scripts"].setEnabled(not aggressive)

    # ------------------------------------------------------------ comando
    def update_command(self) -> list[str] | None:
        targets = self.target.text().strip()
        try:
            if not targets:
                preview = build_args(self.options("OBJETIVO"))
                self.command.setText(display_command(preview[:-1]) + " <objetivo>")
                return None
            args = build_args(self.options(targets))
        except ValidationError as exc:
            self.command.setText(f"⚠  {exc}")
            return None
        self.command.setText(display_command(args))
        return args

    def _request_scan(self) -> None:
        if not self.btn_scan.isEnabled():
            return
        if not self.target.text().strip():
            self.command.setText("⚠  Escribe una IP, rango o dominio a escanear.")
            self.target.setFocus()
            return
        args = self.update_command()
        if args is not None:
            self.scan_requested.emit(args, self.target.text().strip())

    def _copy(self) -> None:
        QGuiApplication.clipboard().setText(self.command.text())
        self.btn_copy.setText("¡Copiado!")

    # ------------------------------------------------------------ estado
    def set_running(self, running: bool, command: str = "") -> None:
        self.btn_scan.setEnabled(not running)
        self.btn_cancel.setVisible(running)
        self.target.setEnabled(not running)
        self.btn_copy.setText("Copiar")
        if running:
            self.console.setPlainText(f"$ {command}\n")
            self.progress.setValue(0)
            self.progress.setRange(0, 0)  # animación indeterminada hasta el primer %
            self.status.setText("Escaneando…")

    def set_progress(self, pct: float) -> None:
        self.progress.setRange(0, 100)
        self.progress.setValue(int(pct))
        self.status.setText(f"Escaneando… {pct:.0f}%")

    def finish(self, message: str) -> None:
        self.progress.setRange(0, 100)
        self.progress.setValue(100)
        self.status.setText(message)

    def append(self, text: str) -> None:
        self.console.moveCursor(QTextCursor.MoveOperation.End)
        self.console.insertPlainText(text)
        self.console.moveCursor(QTextCursor.MoveOperation.End)
