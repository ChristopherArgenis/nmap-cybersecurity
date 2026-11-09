"""Pruebas de la versión moderna con un nmap falso (no se escanea ninguna red)."""
import sys
from pathlib import Path

import pytest
from PySide6.QtCore import QEventLoop, QSettings, QTimer
from PySide6.QtWidgets import QApplication, QMessageBox

from nmap_gui_v2.main_window import ModernWindow
from nmap_gui_v2.theme import THEMES, stylesheet

FAKE = Path(__file__).parent / "fake_nmap.py"


@pytest.fixture(scope="module")
def app():
    return QApplication.instance() or QApplication([])


@pytest.fixture
def window(app, tmp_path, monkeypatch):
    if sys.platform == "win32":
        pytest.skip("envoltorio solo para POSIX")
    wrapper = tmp_path / "nmap"
    wrapper.write_text(f'#!/bin/sh\nexec "{sys.executable}" "{FAKE}" "$@"\n')
    wrapper.chmod(0o755)
    monkeypatch.setattr(QMessageBox, "question", lambda *a, **k: QMessageBox.StandardButton.Yes)
    settings = QSettings(str(tmp_path / "s.ini"), QSettings.Format.IniFormat)
    settings.setValue("nmap_path", str(wrapper))
    w = ModernWindow(history_path=tmp_path / "h.db", settings=settings)
    yield w
    w.close()


def wait_finished(w):
    loop = QEventLoop()
    w.runner.finished.connect(lambda *a: loop.quit())
    QTimer.singleShot(10000, loop.quit)
    loop.exec()


def test_stylesheet_has_no_placeholders():
    for theme in THEMES:
        for key in THEMES[theme]:
            assert "{" + key + "}" not in stylesheet(theme)


def test_profiles_and_command(window):
    sp = window.scan_page
    assert sp.command.text().endswith("<objetivo>")
    sp.target.setText("192.168.1.10")
    sp.select_profile("Puertos y servicios")
    assert sp.command.text() == "nmap -sV -T4 192.168.1.10"
    sp.switches["no_dns"].setChecked(True)
    assert sp.chips["Personalizado"].isChecked()
    assert sp.command.text() == "nmap -sV -T4 -n 192.168.1.10"
    sp.top_ports.setText("50")
    sp.switches["fast"].setChecked(False)
    assert "--top-ports 50" in sp.command.text()
    sp.target.setText("-oN x")
    assert sp.command.text().startswith("⚠")


def test_full_scan_flow(window, app):
    sp = window.scan_page
    sp.target.setText("192.168.1.10")
    sp.select_profile("Escaneo rápido")
    sp._request_scan()
    wait_finished(window)
    app.processEvents()
    assert window.stack.currentWidget() is window.results_page
    rp = window.results_page
    assert rp.host_list.count() == 2
    assert rp.stat_open.value.text() == "2"
    assert [rp.table.item(r, 0).text() for r in range(rp.table.rowCount())] == ["22/tcp", "80/tcp", "443/tcp"]
    rp.only_open.setChecked(True)
    assert rp.table.rowCount() == 2
    rp.filter.setText("ssh")
    assert rp.table.rowCount() == 1
    assert window.history_page.table.rowCount() == 1

    rec_id = window.history.list()[0].id
    window.rerun_record(rec_id)
    wait_finished(window)
    app.processEvents()
    assert window.history_page.table.rowCount() == 2
    window.open_record(rec_id)
    assert window.stack.currentWidget() is rp


def test_theme_switch(window):
    window.apply_theme("claro")
    assert window.settings.value("theme") == "claro"
    assert not window.settings_page.dark.isChecked()
    window.apply_theme("oscuro")
    assert window.settings_page.dark.isChecked()
