import csv
import io
from pathlib import Path

import pytest

from nmap_gui.core import exporter
from nmap_gui.core.history import History
from nmap_gui.core.parser import parse_xml

XML = (Path(__file__).parent / "fixtures" / "sample_scan.xml").read_text()


def test_parse_sample():
    r = parse_xml(XML)
    assert r.hosts_up == 2 and r.elapsed == pytest.approx(12.34)
    h = r.hosts[0]
    assert h.address == "192.168.1.10" and h.mac == "AA:BB:CC:DD:EE:FF" and h.vendor == "Raspberry Pi"
    assert h.hostnames == ["servidor.local"]
    assert h.best_os == "Linux 5.X (96%)"
    assert [p.portid for p in h.open_ports] == [22, 443]
    assert h.ports[0].service_detail == "OpenSSH 9.2p1 Debian"
    assert h.ports[1].scripts["http-title"] == "Panel <admin>"
    assert r.hosts[1].ports[0].state == "open|filtered"


@pytest.mark.parametrize("bad", ["", "no xml", "<otro/>"])
def test_parse_invalid(bad):
    with pytest.raises(ValueError):
        parse_xml(bad)


def test_csv_export():
    rows = list(csv.reader(io.StringIO(exporter.to_csv(parse_xml(XML)))))
    assert rows[0] == exporter.CSV_HEADER
    assert rows[1][:6] == ["192.168.1.10", "servidor.local", "up", "tcp", "22", "open"]
    assert len(rows) == 5


def test_html_export_escapes():
    html = exporter.to_html(parse_xml(XML))
    assert "<admin>" not in html
    assert "OpenSSH 9.2p1 Debian" in html


def test_export_files(tmp_path):
    r = parse_xml(XML)
    for fmt in exporter.FORMATS:
        path = tmp_path / f"out.{fmt}"
        exporter.export(path, fmt, result=r, text_output="texto", xml=XML)
        assert path.read_text(encoding="utf-8")
    with pytest.raises(ValueError):
        exporter.export(tmp_path / "x.csv", "csv", result=None, text_output="", xml="")


def test_history_roundtrip(tmp_path):
    h = History(tmp_path / "sub" / "h.db")
    a = h.add(started_at=1.0, targets="a", command="nmap a", exit_code=0, duration=1.5,
              hosts_up=1, open_ports=2, output="out", xml=XML)
    b = h.add(started_at=2.0, targets="b", command="nmap b", exit_code=1, duration=None,
              hosts_up=0, open_ports=0, output="", xml="")
    assert [r.id for r in h.list()] == [b, a]
    assert h.list()[0].xml == ""  # la lista no carga el XML completo
    assert h.get(a).xml == XML
    h.delete(a)
    assert h.get(a) is None
    h.clear()
    assert h.list() == []
    h.close()
