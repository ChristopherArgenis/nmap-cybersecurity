"""Ejecuta nmap con QProcess sin bloquear la interfaz."""

from __future__ import annotations

import os
import re
import shutil
import sys
import tempfile
import time
from pathlib import Path

from PySide6.QtCore import QObject, QProcess, Signal

from .parser import ScanResult, parse_xml

_PROGRESS_RE = re.compile(r"About ([\d.]+)% done")

_WINDOWS_PATHS = (
    r"C:\Program Files (x86)\Nmap\nmap.exe",
    r"C:\Program Files\Nmap\nmap.exe",
)


def find_nmap(custom_path: str = "") -> str | None:
    """Localiza el ejecutable de nmap (ruta configurada, PATH o rutas típicas)."""
    if custom_path and Path(custom_path).is_file():
        return custom_path
    found = shutil.which("nmap")
    if found:
        return found
    if sys.platform == "win32":
        for p in _WINDOWS_PATHS:
            if Path(p).is_file():
                return p
    for p in ("/usr/bin/nmap", "/usr/local/bin/nmap", "/opt/homebrew/bin/nmap"):
        if Path(p).is_file():
            return p
    return None


def is_admin() -> bool:
    if sys.platform == "win32":
        try:
            import ctypes

            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    return hasattr(os, "geteuid") and os.geteuid() == 0


class ScanRunner(QObject):
    """Lanza un escaneo y emite señales con la salida, el progreso y el resultado."""

    output = Signal(str)
    progress = Signal(float)
    started = Signal(str)
    # (resultado o None, código de salida, texto completo, xml, segundos)
    finished = Signal(object, int, str, str, float)
    failed = Signal(str)

    def __init__(self, parent: QObject | None = None):
        super().__init__(parent)
        self._proc: QProcess | None = None
        self._xml_path = ""
        self._text: list[str] = []
        self._t0 = 0.0
        self._cancelled = False

    @property
    def running(self) -> bool:
        return self._proc is not None and self._proc.state() != QProcess.ProcessState.NotRunning

    def start(self, nmap_path: str, args: list[str]) -> None:
        if self.running:
            raise RuntimeError("Ya hay un escaneo en curso.")
        fd, self._xml_path = tempfile.mkstemp(prefix="nmapgui_", suffix=".xml")
        os.close(fd)
        self._text = []
        self._cancelled = False
        self._t0 = time.time()

        full_args = [*args, "-oX", self._xml_path, "--stats-every", "3s"]
        proc = QProcess(self)
        proc.setProcessChannelMode(QProcess.ProcessChannelMode.MergedChannels)
        proc.readyReadStandardOutput.connect(self._on_ready_read)
        proc.finished.connect(self._on_finished)
        proc.errorOccurred.connect(self._on_error)
        self._proc = proc
        proc.start(nmap_path, full_args)
        self.started.emit(self._xml_path)

    def cancel(self) -> None:
        if self.running:
            self._cancelled = True
            self._proc.terminate()
            if not self._proc.waitForFinished(2000):
                self._proc.kill()

    def _on_ready_read(self) -> None:
        data = bytes(self._proc.readAllStandardOutput()).decode("utf-8", errors="replace")
        if not data:
            return
        self._text.append(data)
        for match in _PROGRESS_RE.finditer(data):
            self.progress.emit(float(match.group(1)))
        self.output.emit(data)

    def _on_error(self, error: QProcess.ProcessError) -> None:
        if error == QProcess.ProcessError.FailedToStart:
            self.failed.emit("No se pudo iniciar nmap. Revisa la ruta en Herramientas → Ruta de nmap.")
            self._cleanup()

    def _on_finished(self, exit_code: int, _status: QProcess.ExitStatus) -> None:
        if self._proc is None:
            return
        self._on_ready_read()
        elapsed = time.time() - self._t0
        text = "".join(self._text)
        xml = ""
        result: ScanResult | None = None
        try:
            xml = Path(self._xml_path).read_text(encoding="utf-8", errors="replace")
            if xml.strip():
                result = parse_xml(xml)
        except (OSError, ValueError):
            # Escaneo cancelado o fallido: el XML puede estar incompleto.
            result = None
        if self._cancelled:
            text += "\n[Escaneo cancelado por el usuario]\n"
        self._cleanup()
        self.finished.emit(result, -1 if self._cancelled else exit_code, text, xml, elapsed)

    def _cleanup(self) -> None:
        if self._xml_path:
            try:
                os.remove(self._xml_path)
            except OSError:
                pass
            self._xml_path = ""
        if self._proc is not None:
            self._proc.deleteLater()
            self._proc = None
