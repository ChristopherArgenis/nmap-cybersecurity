"""Pruebas de la auditoría web y TLS.

Usan servidores falsos en 127.0.0.1 dentro de la propia prueba: no se conectan
a ninguna otra red.
"""
import datetime as dt
import http.server
import ssl
import threading
from pathlib import Path

import pytest

from nmap_gui.core.parser import parse_xml
from nmap_gui_v2.core.extras import extract_extras
from nmap_gui_v2.core.findings import Finding
from nmap_gui_v2.core.webaudit import (
    HttpInfo,
    TlsInfo,
    WebTarget,
    audit_all,
    audit_target,
    evaluate,
    merge_findings,
    web_targets,
)

DEMO = Path(__file__).parent.parent / "nmap_gui_v2" / "data" / "red_ejemplo.xml"


# ------------------------------------------------------- servidores falsos
class Handler(http.server.BaseHTTPRequestHandler):
    routes: dict = {}

    def do_GET(self):  # noqa: N802
        status, headers = self.routes.get(self.server.server_port, (200, {}))
        self.send_response(status)
        for k, v in headers:
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(b"ok")

    def version_string(self):
        return self.routes.get(("server", self.server.server_port), "Prueba")

    def log_message(self, *args):
        pass


def _serve(server):
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    return server


@pytest.fixture
def http_server():
    srv = _serve(http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler))
    yield srv.server_port
    srv.shutdown()
    srv.server_close()


@pytest.fixture
def https_server(tmp_path):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "nas.local")])
    now = dt.datetime.now(dt.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - dt.timedelta(days=1))
            .not_valid_after(now + dt.timedelta(days=10, hours=1)).sign(key, hashes.SHA256()))
    (tmp_path / "c.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (tmp_path / "k.pem").write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()))
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(tmp_path / "c.pem", tmp_path / "k.pem")
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    _serve(srv)
    yield srv.server_port
    srv.shutdown()
    srv.server_close()


def titles(findings):
    return {f.title for f in findings}


# ------------------------------------------------------------- objetivos
def test_web_targets_from_demo():
    xml = DEMO.read_text()
    targets = {(t.host, t.port, t.tls) for t in web_targets(parse_xml(xml), extract_extras(xml))}
    assert ("192.168.1.20", 443, True) in targets and ("192.168.1.20", 80, False) in targets
    assert ("192.168.1.33", 8080, False) in targets  # http-proxy también es web
    assert ("10.20.0.5", 443, True) in targets
    assert not any(port in (22, 445, 554, 9100) for _, port, _ in targets)
    assert WebTarget("h", 443, True).url == "https://h/" and WebTarget("h", 8080, False).url == "http://h:8080/"


# ------------------------------------------------------- servidores reales
def test_http_basic_auth_and_headers(http_server):
    Handler.routes[http_server] = (401, [("WWW-Authenticate", 'Basic realm="camara"')])
    Handler.routes[("server", http_server)] = "lighttpd/1.4.59"
    res = audit_target(WebTarget("127.0.0.1", http_server, False), timeout=3, has_tls_elsewhere=True)
    assert res.http.status == 401 and res.reachable
    t = titles(res.findings)
    assert "Pide contraseña sin cifrar" in t
    assert "No redirige a HTTPS" in t
    assert "El servidor muestra su versión" in t


def test_http_good_redirect(http_server):
    Handler.routes[http_server] = (301, [("Location", "https://127.0.0.1/")])
    Handler.routes[("server", http_server)] = "Prueba"
    res = audit_target(WebTarget("127.0.0.1", http_server, False), timeout=3, has_tls_elsewhere=True)
    assert res.redirects_to_https and res.findings == []


def test_https_certificate_and_cookies(https_server):
    Handler.routes[https_server] = (200, [("Set-Cookie", "sesion=abc; Path=/"),
                                          ("Strict-Transport-Security", "max-age=31536000"),
                                          ("X-Frame-Options", "DENY")])
    Handler.routes[("server", https_server)] = "Prueba"
    res = audit_target(WebTarget("127.0.0.1", https_server, True), timeout=3)
    tls = res.tls
    assert tls.version in ("TLSv1.2", "TLSv1.3") and tls.self_signed
    assert tls.days_left == 10 and tls.key_bits == 2048 and tls.signature == "sha256"
    assert tls.legacy == []  # el servidor solo acepta TLS 1.2+
    t = titles(res.findings)
    assert {"Certificado autofirmado", "Certificado a punto de caducar", "Cookie insegura: sesion"} <= t
    assert "Faltan 3 cabeceras de seguridad" in t
    assert set(res.headers_present) == {"strict-transport-security", "x-frame-options"}


def test_unreachable_service():
    # Puerto local cerrado: no hay hallazgos, solo un error legible.
    import socket
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    res = audit_target(WebTarget("127.0.0.1", port, True), timeout=2)
    assert not res.reachable and res.findings == [] and res.tls.error


def test_audit_all_parallel(http_server):
    Handler.routes[http_server] = (200, [])
    done = []
    results = audit_all([WebTarget("127.0.0.1", http_server, False)] * 3, timeout=3, on_done=done.append)
    assert len(results) == len(done) == 3
    assert audit_all([WebTarget("127.0.0.1", http_server, False)], cancelled=lambda: True) == []


# ------------------------------------------------------ reglas sin conexión
def test_evaluate_rules_offline():
    t = WebTarget("10.0.0.9", 443, True)
    tls = TlsInfo(version="TLSv1", days_left=-5, key_bits=1024, signature="sha1", legacy=["TLS 1.0"])
    res = titles(evaluate(t, HttpInfo(), tls))
    assert {"Usa una versión de TLS obsoleta", "Acepta TLS 1.0 / 1.1", "Certificado caducado",
            "Clave del certificado demasiado corta", "Certificado con firma débil"} <= res
    ec = TlsInfo(version="TLSv1.3", days_left=200, key_bits=256)
    assert evaluate(t, HttpInfo(), ec) == []


def test_merge_findings_dedupes():
    a = Finding("alto", "Acepta TLS 1.0 / 1.1", "", "", "192.168.1.20", "443/tcp", 6, "ssl-enum-ciphers")
    b = Finding("alto", "Acepta TLS 1.0 / 1.1", "", "", "192.168.1.20", "443/tcp", 6, "Auditoría web")
    c = Finding("bajo", "Certificado autofirmado", "", "", "192.168.1.20", "443/tcp", 6, "Auditoría web")
    merged = merge_findings([a], [b, c])
    assert merged == [a, c]


# ---------------------------------------------------------------- interfaz
@pytest.fixture
def window(tmp_path, monkeypatch):
    from PySide6.QtCore import QSettings
    from PySide6.QtWidgets import QApplication, QMessageBox

    from nmap_gui_v2.main_window import ModernWindow

    QApplication.instance() or QApplication([])
    asked = []
    monkeypatch.setattr(QMessageBox, "question",
                        lambda *a, **k: asked.append(a) or QMessageBox.StandardButton.Yes)
    settings = QSettings(str(tmp_path / "s.ini"), QSettings.Format.IniFormat)
    w = ModernWindow(history_path=tmp_path / "h.db", settings=settings)
    w.asked = asked
    yield w
    w.close()


def test_gui_demo_audit_never_connects(window, monkeypatch):
    import nmap_gui_v2.core.webaudit as wa

    monkeypatch.setattr(wa, "audit_target", lambda *a, **k: pytest.fail("¡la demo intentó conectarse!"))
    window.load_demo()
    wp = window.web_page
    assert len(wp.targets) == 8 and wp.btn_audit.isEnabled()
    wp.btn_audit.click()
    assert window.asked == []  # sin conexión, no hace falta pedir permiso
    assert "EJEMPLO" in wp.notice.text()
    assert len(wp.results) == 8
    titles_now = {(f.host, f.title) for f in window.analysis.findings}
    assert ("192.168.1.33", "Pide contraseña sin cifrar") in titles_now
    assert ("192.168.1.20", "Certificado a punto de caducar") in titles_now
    # La cámara pasa a riesgo alto en el mapa por el hallazgo web.
    assert window.analysis.topology.node("192.168.1.33").risk == "alto"
    # Los cambios de la demo siguen ahí.
    assert len(window.analysis.changes.changes) == 4


def test_gui_real_audit_local_server(window, http_server):
    from PySide6.QtCore import QEventLoop, QTimer

    Handler.routes[http_server] = (200, [])
    Handler.routes[("server", http_server)] = "Prueba/2.0"
    xml = f"""<?xml version="1.0"?><nmaprun args="nmap 127.0.0.1"><host><status state="up"/>
    <address addr="127.0.0.1" addrtype="ipv4"/><ports><port protocol="tcp" portid="{http_server}">
    <state state="open"/><service name="http"/></port></ports></host>
    <runstats><finished elapsed="1"/><hosts up="1" down="0"/></runstats></nmaprun>"""
    window.show_result(parse_xml(xml), xml)
    wp = window.web_page
    assert [t.port for t in wp.targets] == [http_server]
    loop = QEventLoop()
    window.web_runner.finished.connect(lambda *_: QTimer.singleShot(0, loop.quit))
    QTimer.singleShot(10000, loop.quit)
    wp.btn_audit.click()
    loop.exec()
    assert window.asked, "debe pedir confirmación antes de conectarse"
    assert len(wp.results) == 1 and next(iter(wp.results.values())).reachable
    assert "El servidor muestra su versión" in {f.title for f in window.analysis.findings}
    assert wp.table.item(0, 6).text().startswith("2 ·")
