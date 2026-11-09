"""Pruebas de la interfaz con un nmap falso (no se escanea ninguna red)."""
import sys
from pathlib import Path

import pytest
from PySide6.QtCore import QEventLoop, QTimer
from PySide6.QtWidgets import QApplication, QMessageBox

from nmap_gui.core.scanner import ScanRunner
from nmap_gui.ui.main_window import MainWindow

FAKE = Path(__file__).parent / "fake_nmap.py"


@pytest.fixture(scope="module")
def app():
    return QApplication.instance() or QApplication([])


@pytest.fixture
def fake_nmap(tmp_path):
    """Envoltorio ejecutable que llama al nmap falso con este intérprete."""
    if sys.platform == "win32":
        pytest.skip("envoltorio solo para POSIX")
    wrapper = tmp_path / "nmap"
    wrapper.write_text(f'#!/bin/sh\nexec "{sys.executable}" "{FAKE}" "$@"\n')
    wrapper.chmod(0o755)
    return str(wrapper)


def wait_for(signal, timeout=10000):
    loop = QEventLoop()
    got = []
    signal.connect(lambda *a: (got.append(a), loop.quit()))
    QTimer.singleShot(timeout, loop.quit)
    loop.exec()
    assert got, "tiempo de espera agotado"
    return got[0]


def test_runner_parses_result(app, fake_nmap):
    runner = ScanRunner()
    progress = []
    runner.progress.connect(progress.append)
    runner.start(fake_nmap, ["-sT", "192.168.1.10"])
    result, code, text, xml, _ = wait_for(runner.finished)
    assert code == 0 and result.hosts_up == 2
    assert "simulado" in text and progress == [50.0]
    assert "<nmaprun" in xml


def test_runner_cancel(app, fake_nmap):
    runner = ScanRunner()
    runner.start(fake_nmap, ["SLOW"])
    QTimer.singleShot(500, runner.cancel)
    result, code, text, _, _ = wait_for(runner.finished)
    assert code == -1 and result is None and "cancelado" in text


def test_runner_missing_binary(app):
    runner = ScanRunner()
    runner.start("/no/existe/nmap", ["h"])
    (msg,) = wait_for(runner.failed)
    assert "nmap" in msg


def test_main_window_full_flow(app, fake_nmap, tmp_path, monkeypatch):
    monkeypatch.setattr(QMessageBox, "question", lambda *a, **k: QMessageBox.StandardButton.Yes)
    win = MainWindow(history_path=tmp_path / "h.db")
    monkeypatch.setattr(win, "nmap_path", lambda: fake_nmap)

    assert win.command.text().endswith("<objetivo>")
    win.profile.setCurrentText("Puertos y servicios")
    win.target.setText("192.168.1.10")
    assert win.command.text() == "nmap -sV -T4 192.168.1.10"
    win.builder.ports.setText("22,443")
    assert win.command.text() == "nmap -p 22,443 -sV -T4 192.168.1.10"
    win.target.setText("-oN x")
    assert win.command.text().startswith("⚠")
    win.target.setText("192.168.1.10")

    win._start_scan()
    wait_for(win.runner.finished)
    app.processEvents()
    assert win.results.tree.topLevelItemCount() == 2
    assert win.history_view.table.rowCount() == 1
    assert win.act_export.isEnabled()

    win.results.only_open.setChecked(True)
    assert win.results.tree.topLevelItem(0).childCount() == 2
    win.results.filter.setText("ssh")
    assert win.results.tree.topLevelItemCount() == 1

    out = tmp_path / "r.html"
    from nmap_gui.core import exporter
    exporter.export(out, "html", **{"result": win._last["result"], "text_output": win._last["text"], "xml": win._last["xml"]})
    assert "OpenSSH" in out.read_text()

    # Repetir desde el historial
    rec_id = win.history.list()[0].id
    win._rerun_history(rec_id)
    wait_for(win.runner.finished)
    app.processEvents()
    assert win.history_view.table.rowCount() == 2
    win.close()
