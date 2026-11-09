"""Panel con casillas y campos para armar el comando nmap visualmente."""

from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QFormLayout,
    QGroupBox,
    QLineEdit,
    QScrollArea,
    QSpinBox,
    QVBoxLayout,
    QWidget,
)

from ..core.command_builder import SCAN_TYPES, TIMING_LABELS, ScanOptions


class BuilderPanel(QScrollArea):
    changed = Signal()

    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent)
        self.setWidgetResizable(True)
        self.setMinimumWidth(340)
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        body = QWidget()
        layout = QVBoxLayout(body)

        # --- Técnica de escaneo ---
        tech = QGroupBox("Técnica")
        f = QFormLayout(tech)
        self.scan_type = QComboBox()
        for flag, label in SCAN_TYPES.items():
            self.scan_type.addItem(f"{label}  {flag}".strip(), flag)
        f.addRow("Tipo:", self.scan_type)
        self.timing = QComboBox()
        self.timing.addItem("Predeterminado", None)
        for level, label in TIMING_LABELS.items():
            self.timing.addItem(label, level)
        f.addRow("Velocidad:", self.timing)
        layout.addWidget(tech)

        # --- Puertos ---
        ports = QGroupBox("Puertos")
        f = QFormLayout(ports)
        self.ports = QLineEdit()
        self.ports.setPlaceholderText("ej. 22,80,443 o 1-1000")
        f.addRow("Lista (-p):", self.ports)
        self.top_ports = QSpinBox()
        self.top_ports.setRange(0, 65535)
        self.top_ports.setSpecialValueText("No usar")
        f.addRow("Más comunes:", self.top_ports)
        self.fast = QCheckBox("Rápido: 100 puertos más comunes (-F)")
        f.addRow(self.fast)
        layout.addWidget(ports)

        # --- Detección ---
        det = QGroupBox("Detección")
        v = QVBoxLayout(det)
        self.service_version = QCheckBox("Versiones de servicios (-sV)")
        self.os_detection = QCheckBox("Sistema operativo (-O, requiere admin)")
        self.default_scripts = QCheckBox("Scripts por defecto (-sC)")
        self.aggressive = QCheckBox("Agresivo: -sV -O -sC --traceroute (-A)")
        for w in (self.service_version, self.os_detection, self.default_scripts, self.aggressive):
            v.addWidget(w)
        sf = QFormLayout()
        self.scripts = QLineEdit()
        self.scripts.setPlaceholderText("ej. http-title,ssl-cert o vuln")
        sf.addRow("Scripts NSE:", self.scripts)
        v.addLayout(sf)
        layout.addWidget(det)

        # --- Descubrimiento y salida ---
        misc = QGroupBox("Otras opciones")
        v = QVBoxLayout(misc)
        self.skip_ping = QCheckBox("No hacer ping, asumir host activo (-Pn)")
        self.no_dns = QCheckBox("Sin resolución DNS (-n)")
        self.verbose = QCheckBox("Salida detallada (-v)")
        self.open_only = QCheckBox("Mostrar solo puertos abiertos (--open)")
        self.ipv6 = QCheckBox("IPv6 (-6)")
        for w in (self.skip_ping, self.no_dns, self.verbose, self.open_only, self.ipv6):
            v.addWidget(w)
        ef = QFormLayout()
        self.extra_args = QLineEdit()
        self.extra_args.setPlaceholderText("Argumentos adicionales, ej. --max-retries 2")
        ef.addRow("Extra:", self.extra_args)
        v.addLayout(ef)
        layout.addWidget(misc)
        layout.addStretch(1)
        self.setWidget(body)

        self._checks = {
            "fast": self.fast,
            "service_version": self.service_version,
            "os_detection": self.os_detection,
            "default_scripts": self.default_scripts,
            "aggressive": self.aggressive,
            "skip_ping": self.skip_ping,
            "no_dns": self.no_dns,
            "verbose": self.verbose,
            "open_only": self.open_only,
            "ipv6": self.ipv6,
        }
        self._texts = {"ports": self.ports, "scripts": self.scripts, "extra_args": self.extra_args}

        for cb in self._checks.values():
            cb.toggled.connect(self.changed)
        for le in self._texts.values():
            le.textChanged.connect(self.changed)
        self.scan_type.currentIndexChanged.connect(self._sync_enabled)
        self.scan_type.currentIndexChanged.connect(self.changed)
        self.timing.currentIndexChanged.connect(self.changed)
        self.top_ports.valueChanged.connect(self.changed)
        self.aggressive.toggled.connect(self._sync_enabled)
        self._sync_enabled()

    def _sync_enabled(self) -> None:
        port_scan = self.scan_type.currentData() != "-sn"
        for w in (self.ports, self.top_ports, self.fast, self.service_version):
            w.setEnabled(port_scan)
        aggressive = self.aggressive.isChecked()
        for w in (self.service_version, self.os_detection, self.default_scripts):
            w.setEnabled(not aggressive and (port_scan or w is not self.service_version))

    def options(self, targets: str) -> ScanOptions:
        opts = ScanOptions(targets=targets)
        opts.scan_type = self.scan_type.currentData() or ""
        opts.timing = self.timing.currentData()
        opts.top_ports = self.top_ports.value() or None
        for name, cb in self._checks.items():
            setattr(opts, name, cb.isChecked())
        for name, le in self._texts.items():
            setattr(opts, name, le.text())
        return opts

    def set_options(self, opts: ScanOptions) -> None:
        widgets = [self.scan_type, self.timing, self.top_ports, *self._checks.values(), *self._texts.values()]
        for w in widgets:
            w.blockSignals(True)
        try:
            self.scan_type.setCurrentIndex(max(0, self.scan_type.findData(opts.scan_type)))
            idx = self.timing.findData(opts.timing) if opts.timing is not None else 0
            self.timing.setCurrentIndex(max(0, idx))
            self.top_ports.setValue(opts.top_ports or 0)
            for name, cb in self._checks.items():
                cb.setChecked(getattr(opts, name))
            for name, le in self._texts.items():
                le.setText(getattr(opts, name))
        finally:
            for w in widgets:
                w.blockSignals(False)
        self._sync_enabled()
        self.changed.emit()
