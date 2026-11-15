"""Ejecuta la auditoría web en segundo plano sin congelar la ventana."""

from __future__ import annotations

import threading

from PySide6.QtCore import QObject, Signal

from .core.webaudit import WebTarget, audit_all


class WebAuditRunner(QObject):
    progress = Signal(int, int)  # hechos, total
    finished = Signal(list)  # lista de WebResult

    def __init__(self, parent: QObject | None = None):
        super().__init__(parent)
        self._thread: threading.Thread | None = None
        self._cancel = False

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def start(self, targets: list[WebTarget], timeout: float = 5.0) -> None:
        if self.running:
            return
        self._cancel = False
        total = len(targets)
        done = [0]

        def on_done(_result):
            done[0] += 1
            self.progress.emit(done[0], total)

        def work():
            results = audit_all(targets, timeout, on_done=on_done, cancelled=lambda: self._cancel)
            self.finished.emit(results)

        self.progress.emit(0, total)
        self._thread = threading.Thread(target=work, daemon=True)
        self._thread.start()

    def cancel(self) -> None:
        self._cancel = True

    def wait(self, timeout: float | None = None) -> None:
        if self._thread is not None:
            self._thread.join(timeout)
