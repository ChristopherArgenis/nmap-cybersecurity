"""Auditoría web y TLS de los paneles que encontró nmap.

Se conecta a cada servicio web (HTTP/HTTPS) de los equipos escaneados y revisa
cifrado, certificado, redirección a HTTPS y cabeceras de seguridad. Solo hace
una petición GET a "/" y unos pocos saludos TLS por servicio: no prueba
contraseñas ni ataca nada. Úsala solo en equipos propios o con permiso.
"""

from __future__ import annotations

import http.client
import re
import socket
import ssl
import warnings
from dataclasses import dataclass, field
from datetime import datetime, timezone

from nmap_gui.core.parser import ScanResult

from .extras import HostExtras
from .findings import SEVERITY_RANK, Finding, _ip_key

SECURITY_HEADERS = {
    "strict-transport-security": "HSTS (obliga a usar HTTPS)",
    "content-security-policy": "Content-Security-Policy (limita scripts)",
    "x-frame-options": "X-Frame-Options (evita clickjacking)",
    "x-content-type-options": "X-Content-Type-Options (evita confundir tipos de archivo)",
    "referrer-policy": "Referrer-Policy (controla qué se comparte al salir)",
}
SOURCE = "Auditoría web"


@dataclass(frozen=True)
class WebTarget:
    host: str
    port: int
    tls: bool
    name: str = ""

    @property
    def url(self) -> str:
        scheme = "https" if self.tls else "http"
        default = 443 if self.tls else 80
        port = "" if self.port == default else f":{self.port}"
        return f"{scheme}://{self.host}{port}/"

    @property
    def port_label(self) -> str:
        return f"{self.port}/tcp"


@dataclass
class TlsInfo:
    version: str = ""
    cipher: str = ""
    subject: str = ""
    issuer: str = ""
    not_after: datetime | None = None
    days_left: int | None = None
    self_signed: bool = False
    key_bits: int | None = None
    signature: str = ""
    legacy: list[str] = field(default_factory=list)  # versiones antiguas aceptadas
    legacy_checked: bool = False
    error: str = ""


@dataclass
class HttpInfo:
    status: int | None = None
    headers: dict[str, str] = field(default_factory=dict)  # nombres en minúsculas
    cookies: list[str] = field(default_factory=list)
    location: str = ""
    error: str = ""

    @property
    def server(self) -> str:
        return self.headers.get("server", "")


@dataclass
class WebResult:
    target: WebTarget
    http: HttpInfo = field(default_factory=HttpInfo)
    tls: TlsInfo | None = None
    findings: list[Finding] = field(default_factory=list)
    example: bool = False  # resultado de la demostración, no de una conexión real

    @property
    def reachable(self) -> bool:
        return self.http.status is not None or bool(self.tls and self.tls.version)

    @property
    def headers_present(self) -> list[str]:
        return [h for h in SECURITY_HEADERS if h in self.http.headers]

    @property
    def headers_missing(self) -> list[str]:
        relevant = SECURITY_HEADERS if self.target.tls else {
            k: v for k, v in SECURITY_HEADERS.items() if k != "strict-transport-security"}
        return [h for h in relevant if h not in self.http.headers]

    @property
    def redirects_to_https(self) -> bool:
        return self.http.location.lower().startswith("https://")

    @property
    def worst(self) -> str:
        if not self.findings:
            return ""
        return min((f.severity for f in self.findings), key=SEVERITY_RANK.__getitem__)


# --------------------------------------------------------------- objetivos
def web_targets(result: ScanResult | None, extras: dict[str, HostExtras]) -> list[WebTarget]:
    """Servicios web abiertos según el escaneo."""
    if result is None:
        return []
    out = []
    for h in result.hosts:
        if h.status != "up":
            continue
        ex = extras.get(h.address, HostExtras())
        name = h.hostnames[0] if h.hostnames else ""
        for p in h.ports:
            if p.state != "open" or p.protocol != "tcp":
                continue
            svc = p.service.lower()
            tls = ("tcp", p.portid) in ex.ssl_ports or svc in ("https", "https-alt")
            if svc.startswith("http") or svc in ("ssl", "https") or (tls and svc in ("", "ssl", "unknown")):
                out.append(WebTarget(h.address, p.portid, tls, name))
    return out


# ------------------------------------------------------------------ red
def _no_verify_context() -> ssl.SSLContext:
    # Los equipos de casa suelen tener certificados autofirmados: no se valida
    # la cadena para poder revisarlos; el certificado se analiza aparte.
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def check_tls(host: str, port: int, timeout: float = 5.0) -> TlsInfo:
    info = TlsInfo()
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with _no_verify_context().wrap_socket(raw, server_hostname=None) as tls:
                info.version = tls.version() or ""
                cipher = tls.cipher()
                info.cipher = cipher[0] if cipher else ""
                der = tls.getpeercert(binary_form=True)
        if der:
            _describe_certificate(der, info)
    except (OSError, ssl.SSLError) as exc:
        info.error = _friendly_error(exc)
        return info

    info.legacy, info.legacy_checked = _legacy_versions(host, port, timeout)
    return info


def _legacy_versions(host: str, port: int, timeout: float) -> tuple[list[str], bool]:
    """Prueba si el servidor acepta TLS 1.0 o 1.1 (si este equipo puede ofrecerlos)."""
    accepted, checked = [], False
    for name, version in (("TLS 1.0", ssl.TLSVersion.TLSv1), ("TLS 1.1", ssl.TLSVersion.TLSv1_1)):
        try:
            with warnings.catch_warnings():
                # Python avisa que TLS 1.0/1.1 están obsoletos: justo eso queremos comprobar.
                warnings.simplefilter("ignore", DeprecationWarning)
                ctx = _no_verify_context()
                ctx.minimum_version = version
                ctx.maximum_version = version
            ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
        except (ValueError, ssl.SSLError):
            continue  # el OpenSSL local no permite probar esta versión
        checked = True
        try:
            with socket.create_connection((host, port), timeout=timeout) as raw:
                with ctx.wrap_socket(raw, server_hostname=None):
                    accepted.append(name)
        except (OSError, ssl.SSLError):
            pass
    return accepted, checked


def _describe_certificate(der: bytes, info: TlsInfo) -> None:
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import dsa, ec, rsa

    cert = x509.load_der_x509_certificate(der)
    info.subject = cert.subject.rfc4514_string()
    info.issuer = cert.issuer.rfc4514_string()
    info.self_signed = cert.subject == cert.issuer
    info.not_after = cert.not_valid_after_utc
    info.days_left = (info.not_after - datetime.now(timezone.utc)).days
    algo = cert.signature_hash_algorithm
    info.signature = algo.name if algo else ""
    key = cert.public_key()
    if isinstance(key, (rsa.RSAPublicKey, dsa.DSAPublicKey)):
        info.key_bits = key.key_size
    elif isinstance(key, ec.EllipticCurvePublicKey):
        info.key_bits = key.curve.key_size


def check_http(target: WebTarget, timeout: float = 5.0) -> HttpInfo:
    info = HttpInfo()
    if target.tls:
        conn = http.client.HTTPSConnection(target.host, target.port, timeout=timeout, context=_no_verify_context())
    else:
        conn = http.client.HTTPConnection(target.host, target.port, timeout=timeout)
    try:
        conn.request("GET", "/", headers={"User-Agent": "NMAP-Studio-auditoria/2", "Connection": "close"})
        resp = conn.getresponse()
        info.status = resp.status
        for k, v in resp.getheaders():
            k = k.lower()
            if k == "set-cookie":
                info.cookies.append(v)
            else:
                info.headers[k] = v
        info.location = info.headers.get("location", "")
        resp.read(65536)
    except (OSError, ssl.SSLError, http.client.HTTPException) as exc:
        info.error = _friendly_error(exc)
    finally:
        conn.close()
    return info


def _friendly_error(exc: Exception) -> str:
    if isinstance(exc, socket.timeout):
        return "No respondió a tiempo"
    if isinstance(exc, ConnectionRefusedError):
        return "Conexión rechazada"
    if isinstance(exc, ssl.SSLError):
        return f"Error de TLS: {exc.reason or exc}"
    return str(exc) or exc.__class__.__name__


# ------------------------------------------------------------ hallazgos
def evaluate(target: WebTarget, http_info: HttpInfo, tls: TlsInfo | None,
             has_tls_elsewhere: bool = False) -> list[Finding]:
    """Convierte lo observado en hallazgos (sin conectarse a nada)."""
    out: list[Finding] = []

    def add(sev, title, detail, rec, layer):
        out.append(Finding(sev, title, detail, rec, target.host, target.port_label, layer, SOURCE))

    if tls and tls.version:
        if tls.version in ("TLSv1", "TLSv1.1", "SSLv3"):
            add("alto", "Usa una versión de TLS obsoleta",
                f"La conexión se negoció con {tls.version}.",
                "Actualiza el equipo o su configuración para usar TLS 1.2 o 1.3.", 6)
        if tls.legacy:
            add("alto", "Acepta TLS 1.0 / 1.1",
                f"Acepta {' y '.join(tls.legacy)}, versiones que ya no se consideran seguras.",
                "En la configuración del equipo deja solo TLS 1.2 y 1.3.", 6)
        if tls.days_left is not None and tls.days_left < 0:
            add("alto", "Certificado caducado",
                f"Caducó hace {-tls.days_left} días; el navegador mostrará advertencias.",
                "Renueva el certificado del equipo.", 6)
        elif tls.days_left is not None and tls.days_left < 30:
            add("bajo", "Certificado a punto de caducar",
                f"Caduca en {tls.days_left} días.", "Renueva el certificado antes de que caduque.", 6)
        if tls.self_signed:
            add("bajo", "Certificado autofirmado",
                "Es normal en equipos de casa, pero el navegador no puede comprobar que hablas con el equipo real.",
                "Si accedes a menudo, instala un certificado de tu propia autoridad o de Let’s Encrypt.", 6)
        # Claves de curva elíptica (256–521 bits) son seguras; solo se avisan RSA cortas.
        if tls.key_bits is not None and 521 < tls.key_bits < 2048:
            add("medio", "Clave del certificado demasiado corta",
                f"La clave RSA es de {tls.key_bits} bits.", "Usa una clave RSA de 2048 bits o más.", 6)
        if tls.signature in ("sha1", "md5"):
            add("medio", "Certificado con firma débil",
                f"El certificado está firmado con {tls.signature.upper()}.",
                "Genera un certificado nuevo firmado con SHA-256.", 6)

    h = http_info
    if h.status is None:
        return out

    if not target.tls:
        auth = h.headers.get("www-authenticate", "")
        if h.status == 401 and auth.lower().startswith("basic"):
            add("alto", "Pide contraseña sin cifrar",
                "El panel pide usuario y contraseña por HTTP: viajan por la red sin cifrar.",
                "Entra solo por HTTPS o activa HTTPS en el equipo.", 7)
        if has_tls_elsewhere and not h.location.lower().startswith("https://"):
            add("bajo", "No redirige a HTTPS",
                "El equipo tiene HTTPS, pero la versión sin cifrar no te lleva a ella.",
                "Activa la redirección automática de HTTP a HTTPS.", 6)

    missing = [SECURITY_HEADERS[k] for k in SECURITY_HEADERS
               if k not in h.headers and (target.tls or k != "strict-transport-security")]
    if missing and 200 <= h.status < 300:
        add("bajo", f"Faltan {len(missing)} cabeceras de seguridad",
            "No envía: " + "; ".join(missing) + ".",
            "Si el equipo lo permite, actívalas; si es un dispositivo, mantén su firmware al día.", 7)

    if re.search(r"\d", h.server):
        add("bajo", "El servidor muestra su versión",
            f"Responde «Server: {h.server}». Ayuda a un atacante a buscar fallos conocidos.",
            "Oculta la versión en la configuración del servidor o actualiza el firmware.", 7)

    for cookie in h.cookies:
        attrs = cookie.lower()
        name = cookie.split("=", 1)[0].strip()
        problems = []
        if "httponly" not in attrs:
            problems.append("sin HttpOnly (un script puede leerla)")
        if target.tls and "secure" not in attrs:
            problems.append("sin Secure (puede enviarse sin cifrar)")
        if problems:
            add("medio", f"Cookie insegura: {name}",
                "La cookie de sesión se envía " + " y ".join(problems) + ".",
                "Configura las cookies con HttpOnly y Secure.", 7)
    return out


def audit_target(target: WebTarget, timeout: float = 5.0, has_tls_elsewhere: bool = False) -> WebResult:
    """Revisa un servicio web: TLS (si lo usa) y la respuesta HTTP."""
    tls = check_tls(target.host, target.port, timeout) if target.tls else None
    http_info = check_http(target, timeout)
    findings = evaluate(target, http_info, tls, has_tls_elsewhere)
    return WebResult(target, http_info, tls, findings)


def audit_all(targets: list[WebTarget], timeout: float = 5.0, on_done=None, cancelled=lambda: False,
              workers: int = 4) -> list[WebResult]:
    """Audita varios servicios en paralelo. `on_done(result)` se llama tras cada uno."""
    from concurrent.futures import ThreadPoolExecutor

    tls_hosts = {t.host for t in targets if t.tls}
    results: list[WebResult] = []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = []
        for t in targets:
            futures.append(pool.submit(
                lambda t=t: None if cancelled() else audit_target(t, timeout, t.host in tls_hosts)))
        for fut in futures:
            res = fut.result()
            if res is None:
                continue
            results.append(res)
            if on_done:
                on_done(res)
    return results


def merge_findings(base: list[Finding], extra: list[Finding]) -> list[Finding]:
    """Une hallazgos sin repetir el mismo problema en el mismo equipo."""
    seen = {(f.host, f.title) for f in base}
    merged = list(base) + [f for f in extra if (f.host, f.title) not in seen]
    merged.sort(key=lambda f: (SEVERITY_RANK[f.severity], _ip_key(f.host), f.port))
    return merged
