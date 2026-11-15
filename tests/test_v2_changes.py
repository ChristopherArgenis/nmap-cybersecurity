"""Pruebas de la vigilancia de cambios (versión 2). No escanean ninguna red."""
from pathlib import Path

from PySide6.QtCore import QSettings
from PySide6.QtWidgets import QApplication

from nmap_gui.core.parser import parse_xml
from nmap_gui_v2.core.analysis import analyze_scan
from nmap_gui_v2.core.changes import compare

DATA = Path(__file__).parent.parent / "nmap_gui_v2" / "data"
NOW = (DATA / "red_ejemplo.xml").read_text()
BEFORE = (DATA / "red_ejemplo_anterior.xml").read_text()


def test_compare_demo_networks():
    cs = compare(parse_xml(BEFORE), parse_xml(NOW), "antes", "ahora")
    kinds = [(c.kind, c.host, c.port) for c in cs.changes]
    assert ("host_nuevo", "192.168.1.25", "") in kinds
    assert ("puerto_abierto", "192.168.1.33", "8080/tcp") in kinds
    assert ("puerto_cerrado", "192.168.1.40", "22/tcp") in kinds
    assert ("servicio_cambiado", "192.168.1.20", "80/tcp") in kinds
    assert cs.new_hosts == {"192.168.1.25"} and cs.opened == {"192.168.1.33": ["8080/tcp"]}
    # Lo más importante primero; lo positivo (puerto cerrado) al final.
    assert cs.changes[-1].severity == "info"


def test_compare_reverse_and_identical():
    back = compare(parse_xml(NOW), parse_xml(BEFORE))
    assert [c.kind for c in back.of_kind("host_desaparecido")] == ["host_desaparecido"]
    assert compare(parse_xml(NOW), parse_xml(NOW)).empty
    assert compare(None, parse_xml(NOW)).empty


def test_risky_new_port_is_high():
    before = NOW.replace('<port protocol="tcp" portid="23"><state state="open" reason="syn-ack"/><service name="telnet"/></port>', "")
    cs = compare(parse_xml(before), parse_xml(NOW))
    telnet = [c for c in cs.changes if c.port == "23/tcp"]
    assert telnet and telnet[0].severity == "alto"


def test_analysis_marks_changed_nodes():
    a = analyze_scan(parse_xml(NOW), NOW, parse_xml(BEFORE))
    assert a.topology.node("192.168.1.25").change == "nuevo"
    assert a.topology.node("192.168.1.33").change == "+1 puerto"
    assert a.topology.node("192.168.1.10").change == ""
    assert analyze_scan(parse_xml(NOW), NOW).changes.empty


def test_gui_changes(tmp_path):
    from nmap_gui_v2.main_window import ModernWindow

    app = QApplication.instance() or QApplication([])
    settings = QSettings(str(tmp_path / "s.ini"), QSettings.Format.IniFormat)
    w = ModernWindow(history_path=tmp_path / "h.db", settings=settings)
    cp = w.changes_page
    assert cp.stat_new.value.text() == "—"
    w.load_demo()
    app.processEvents()
    assert cp.stat_new.value.text() == "1" and cp.stat_open.value.text() == "1"
    assert cp.stat_closed.value.text() == "1" and cp.stat_other.value.text() == "1"
    w.topology_page.select("192.168.1.33")
    assert w.topology_page.d_change_label.isVisibleTo(w.topology_page)

    # Dos escaneos guardados de los mismos objetivos: se comparan solos.
    for when, xml in ((1000.0, BEFORE), (2000.0, NOW)):
        w.history.add(started_at=when, targets="192.168.1.0/24", command="nmap 192.168.1.0/24",
                      exit_code=0, duration=1.0, hosts_up=7, open_ports=0, output="", xml=xml)
    w._reload_history()
    assert cp.before.count() == 2 and cp.btn_compare.isEnabled()
    newest = w.history.list()[0].id
    w.open_record(newest)
    assert len(w.analysis.changes.changes) == 4
    assert w.analysis.changes.before_label.startswith("Escaneo del")

    # Comparación manual, aunque se elijan al revés.
    oldest = w.history.list()[1].id
    w.compare_records(newest, oldest)
    assert cp.stat_new.value.text() == "1"
    w.close()
