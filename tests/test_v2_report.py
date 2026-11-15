"""Pruebas del reporte PDF (versión 2). No escanean ninguna red."""
from pathlib import Path

import pytest
from PySide6.QtCore import QSettings
from PySide6.QtWidgets import QApplication

from nmap_gui.core.parser import parse_xml
from nmap_gui_v2.core.analysis import analyze_scan
from nmap_gui_v2.core.report import MAP_IMAGE, ReportMeta, build_report_html

DATA = Path(__file__).parent.parent / "nmap_gui_v2" / "data"
NOW = (DATA / "red_ejemplo.xml").read_text()
BEFORE = (DATA / "red_ejemplo_anterior.xml").read_text()


def test_report_html_sections_and_escaping():
    a = analyze_scan(parse_xml(NOW), NOW, parse_xml(BEFORE), "antes", "ahora")
    meta = ReportMeta(author="<script>x</script>", scope="192.168.1.0/24", command=a.result.command, demo=True)
    doc = build_report_html(a, [], meta)
    for section in ("1. Resumen ejecutivo", "2. Mapa de la red", "3. Equipos encontrados",
                    "4. Hallazgos por capa del modelo OSI", "5. Cambios desde el escaneo anterior",
                    "7. Metodología y alcance", "DATOS DE EJEMPLO", MAP_IMAGE):
        assert section in doc, section
    assert "<script>" not in doc and "&lt;script&gt;" in doc
    assert "Requiere atención" in doc  # hay hallazgos altos
    assert "SMBv1 habilitado" in doc and "Capa 6" in doc
    assert "6. Auditoría web" not in doc  # sin auditoría, sin esa sección


def test_report_without_findings_or_map():
    xml = """<?xml version="1.0"?><nmaprun args="nmap x"><host><status state="up"/>
    <address addr="10.0.0.2" addrtype="ipv4"/><ports/></host><runstats><finished elapsed="1"/>
    <hosts up="1" down="0"/></runstats></nmaprun>"""
    a = analyze_scan(parse_xml(xml), xml)
    doc = build_report_html(a, [], ReportMeta(include_map=False))
    assert "Muy bueno" in doc and "No se detectaron hallazgos" in doc and MAP_IMAGE not in doc


@pytest.fixture
def window(tmp_path):
    from nmap_gui_v2.main_window import ModernWindow

    QApplication.instance() or QApplication([])
    settings = QSettings(str(tmp_path / "s.ini"), QSettings.Format.IniFormat)
    settings.setValue("report_author", "Equipo de prueba")
    w = ModernWindow(history_path=tmp_path / "h.db", settings=settings)
    yield w
    w.close()


def test_gui_generates_pdf(window, tmp_path):
    assert window.settings_page.author.text() == "Equipo de prueba"
    window.load_demo()
    window.web_page.btn_audit.click()  # resultados de ejemplo, sin conexión
    out = window.generate_report(str(tmp_path / "informe.pdf"))
    data = Path(out).read_bytes()
    assert data.startswith(b"%PDF") and len(data) > 30_000  # incluye la imagen del mapa
    assert window.topology_page.theme == window.theme  # el mapa vuelve a su tema tras la captura


def test_gui_report_needs_data(window, monkeypatch):
    from PySide6.QtWidgets import QMessageBox

    shown = []
    monkeypatch.setattr(QMessageBox, "information", lambda *a, **k: shown.append(a))
    assert window.generate_report("/no/importa.pdf") is None and shown
