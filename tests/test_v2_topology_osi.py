"""Pruebas de hallazgos, topología y modelo OSI (versión 2). No escanean ninguna red."""
from pathlib import Path

import pytest
from PySide6.QtCore import QSettings
from PySide6.QtWidgets import QApplication

from nmap_gui.core.command_builder import build_args
from nmap_gui.core.parser import parse_xml
from nmap_gui_v2.core.analysis import analyze_scan
from nmap_gui_v2.core.extras import extract_extras
from nmap_gui_v2.core.findings import worst
from nmap_gui_v2.core.osi import LAYERS, build_osi, suggested_options
from nmap_gui_v2.core.topology import NODE_H, NODE_W, layout

FIXTURES = Path(__file__).parent / "fixtures"
HOME = (FIXTURES / "home_network.xml").read_text()
SAMPLE = (FIXTURES / "sample_scan.xml").read_text()


@pytest.fixture(scope="module")
def home():
    return analyze_scan(parse_xml(HOME), HOME)


# ---------------------------------------------------------------- extras
def test_extras():
    ex = extract_extras(HOME)
    assert ex["192.168.1.33"].device_type == "webcam"
    assert ex["192.168.1.10"].os_family == "Windows"
    assert ex["10.20.0.5"].distance == 3
    assert ex["10.20.0.5"].hops == ["192.168.1.1", "10.20.0.1", "10.20.0.5"]
    assert ("tcp", 443) in ex["192.168.1.20"].ssl_ports
    assert ("tcp", 80) not in ex["192.168.1.20"].ssl_ports
    assert extract_extras("") == {} and extract_extras("no es xml") == {}


# -------------------------------------------------------------- hallazgos
def test_findings(home):
    titles = {(f.host, f.title): f for f in home.findings}
    assert titles[("192.168.1.20", "Acepta TLS 1.0 / 1.1")].layer == 6
    assert titles[("192.168.1.20", "SMBv1 habilitado")].severity == "alto"
    assert titles[("192.168.1.40", "Telnet abierto")].severity == "alto"
    assert titles[("192.168.1.33", "Panel web sin cifrar")].port == "80/tcp, 8080/tcp"
    assert ("192.168.1.10", "SMBv1 habilitado") not in titles  # su SMB es moderno
    assert ("192.168.1.10", "Carpetas compartidas (SMB) visibles") in titles
    assert ("192.168.1.25", "Panel web sin cifrar") not in titles  # solo SSH
    sev = [f.severity for f in home.findings]
    assert sev == sorted(sev, key=("critico", "alto", "medio", "bajo").index)
    assert worst([]) == ""


def test_findings_without_extras_do_not_crash():
    a = analyze_scan(parse_xml(SAMPLE), "")
    assert a.findings  # sin XML extra sigue funcionando
    assert analyze_scan(None, "").topology.nodes == []


# -------------------------------------------------------------- topología
def test_topology_structure(home):
    t = home.topology
    assert t.subnet == "192.168.1.0/24"
    kinds = {n.id: n.kind for n in t.nodes}
    assert kinds["192.168.1.1"] == "gateway"
    assert kinds["192.168.1.33"] == "camera"
    assert kinds["192.168.1.40"] == "printer"
    assert kinds["192.168.1.20"] == "storage"
    assert kinds["192.168.1.10"] == "computer"
    assert t.node("192.168.1.15").label == "Apple"
    edges = {(e.a, e.b) for e in t.edges}
    assert ("internet", "192.168.1.1") in edges and ("192.168.1.1", "hub") in edges
    assert ("hub", "192.168.1.33") in edges
    assert ("192.168.1.1", "hop:10.20.0.1") in edges and ("hop:10.20.0.1", "10.20.0.5") in edges
    assert t.node("10.20.0.5").zone == "remotos"
    assert t.node("192.168.1.20").risk == "alto"
    assert t.node("192.168.1.25").risk == ""


def test_topology_without_router():
    # Sin router ni .1/.254 escaneados: todos cuelgan de la red local, sin Internet.
    t = analyze_scan(parse_xml(SAMPLE), SAMPLE).topology
    assert t.node("internet") is None
    assert {(e.a, e.b) for e in t.edges} == {("hub", "192.168.1.10"), ("hub", "192.168.1.20")}


def test_topology_gateway_by_address():
    # Si no hay router detectado pero se escaneó la .1, se usa como puerta de enlace.
    xml = SAMPLE.replace("192.168.1.20", "192.168.1.1")
    t = analyze_scan(parse_xml(xml), xml).topology
    assert t.node("192.168.1.1").kind == "gateway"
    assert ("internet", "192.168.1.1") in {(e.a, e.b) for e in t.edges}


def test_layout_no_overlaps(home):
    lay = layout(home.topology)
    assert set(lay.positions) == {n.id for n in home.topology.nodes}
    pts = list(lay.positions.values())
    for i, (x1, y1) in enumerate(pts):
        for x2, y2 in pts[i + 1:]:
            assert abs(x1 - x2) >= NODE_W or abs(y1 - y2) >= NODE_H
    # La zona remota queda a la derecha de las demás.
    rx = lay.zones["remotos"][0]
    assert all(rx >= x + w for z, (x, y, w, h) in lay.zones.items() if z != "remotos")


# ------------------------------------------------------------------- OSI
def test_osi_whole_network(home):
    osi = {s.layer.number: s for s in build_osi(home.result, home.extras, home.findings)}
    assert [s for s in osi] == [7, 6, 5, 4, 3, 2, 1]
    assert {"Telnet", "RDP", "SSH", "RTSP"} <= set(osi[7].protocols)
    assert "TLS 1.0" in osi[6].protocols and "HTTP sin cifrar" in osi[6].protocols
    assert "SMB" in osi[5].protocols
    assert osi[4].protocols == ["TCP · 20 abiertos", "UDP · 2 abiertos"]
    assert "ICMP" in osi[3].protocols and "ARP" in osi[2].protocols
    assert osi[1].protocols == [] and osi[1].findings == []
    assert sum(len(s.findings) for s in osi.values()) == len(home.findings)


def test_osi_single_host(home):
    osi = {s.layer.number: s for s in build_osi(home.result, home.extras, home.findings, "192.168.1.40")}
    assert set(osi[7].protocols) == {"Telnet", "HTTP", "IPP", "JetDirect"}
    assert all(f.host == "192.168.1.40" for s in osi.values() for f in s.findings)
    assert osi[2].protocols == ["ARP", "MAC · 1 equipo"]


def test_layer_suggestions_build_valid_commands():
    for layer in LAYERS:
        if layer.suggestion_text:
            args = build_args(suggested_options(layer.number, "192.168.1.0/24"))
            assert args[-1] == "192.168.1.0/24"
    assert "--script=ssl-enum-ciphers,ssl-cert" in build_args(suggested_options(6, "h"))


# ------------------------------------------------------------------ interfaz
@pytest.fixture
def window(tmp_path):
    from nmap_gui_v2.main_window import ModernWindow

    app = QApplication.instance() or QApplication([])
    settings = QSettings(str(tmp_path / "s.ini"), QSettings.Format.IniFormat)
    w = ModernWindow(history_path=tmp_path / "h.db", settings=settings)
    w.load_xml_file(str(FIXTURES / "home_network.xml"))
    app.processEvents()
    yield w
    w.close()


def test_gui_topology_page(window, tmp_path):
    tp = window.topology_page
    assert len(tp.items) == len(window.analysis.topology.nodes)
    tp.select("192.168.1.20")
    assert tp.d_title.text() == "nas"
    assert tp.d_values["Fabricante"].text() == "Synology Incorporated"
    assert tp.btn_scan.isVisible() or not tp.isVisible()
    tp.only_findings.setChecked(True)
    assert tp.items["192.168.1.25"].dimmed and not tp.items["192.168.1.20"].dimmed
    out = tp.export_png(str(tmp_path / "mapa.png"))
    assert Path(out).stat().st_size > 1000

    tp.scan_host.emit("192.168.1.20")
    assert window.scan_page.target.text() == "192.168.1.20"
    assert window.stack.currentWidget() is window.scan_page


def test_gui_osi_page(window):
    op = window.osi_page
    assert [c.number for c in op.cards] == [7, 6, 5, 4, 3, 2, 1]
    # Se despliega sola la capa con el hallazgo más grave.
    assert [c.number for c in op.cards if not c.body.isHidden()] == [7]
    op.card(6).set_expanded(True)
    op.focus_host("192.168.1.40")
    assert op.current_host() == "192.168.1.40"
    assert not op.card(6).body.isHidden()  # se mantiene abierta al cambiar de equipo
    assert all(f.host == "192.168.1.40" for c in op.cards for f in c.summary.findings)

    window.topology_page.show_osi.emit("192.168.1.20")
    assert op.current_host() == "192.168.1.20"

    op.investigate.emit(6, "192.168.1.20")
    sp = window.scan_page
    assert sp.chips["Personalizado"].isChecked()
    assert sp.command.text() == "nmap -p 443,465,636,993,995,8443 --script=ssl-enum-ciphers,ssl-cert -T4 192.168.1.20"
    op.investigate.emit(3, "")
    assert sp.command.text().endswith("--traceroute " + window._current["targets"])


def test_gui_theme_switch_keeps_pages(window):
    window.apply_theme("claro")
    window.topology_page.select("192.168.1.33")
    window.apply_theme("oscuro")
    assert window.topology_page.d_title.text() == "Cámara IP"
    assert len(window.osi_page.cards) == 7
