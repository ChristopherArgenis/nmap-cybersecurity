"""Hallazgos de seguridad deducidos de un escaneo, con reglas sencillas.

Las severidades son orientativas: indican qué revisar primero en una red propia,
no sustituyen una auditoría profesional.
"""

from __future__ import annotations

from dataclasses import dataclass

from nmap_gui.core.parser import Host, Port, ScanResult

from .extras import HostExtras

SEVERITIES = ("critico", "alto", "medio", "bajo")
SEVERITY_LABELS = {"critico": "Crítico", "alto": "Alto", "medio": "Medio", "bajo": "Bajo"}
SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITIES)}

DATABASE_PORTS = {
    1433: "SQL Server",
    3306: "MySQL",
    5432: "PostgreSQL",
    6379: "Redis",
    9200: "Elasticsearch",
    27017: "MongoDB",
}


@dataclass(frozen=True)
class Finding:
    severity: str
    title: str
    detail: str
    recommendation: str
    host: str
    port: str  # "443/tcp", varios separados por coma, o "" si afecta al equipo entero
    layer: int  # capa OSI (1–7)
    source: str  # qué lo detectó: "nmap", "ssl-enum-ciphers"…

    @property
    def severity_label(self) -> str:
        return SEVERITY_LABELS[self.severity]


def worst(findings: list[Finding]) -> str:
    """Severidad más alta de la lista, o "" si está vacía."""
    if not findings:
        return ""
    return min((f.severity for f in findings), key=SEVERITY_RANK.__getitem__)


def analyze(result: ScanResult | None, extras: dict[str, HostExtras]) -> list[Finding]:
    if result is None:
        return []
    found: list[Finding] = []
    for host in result.hosts:
        found += _analyze_host(host, extras.get(host.address, HostExtras()))
    found.sort(key=lambda f: (SEVERITY_RANK[f.severity], _ip_key(f.host), f.port))
    return found


def _ip_key(ip: str) -> tuple:
    parts = ip.split(".")
    if len(parts) == 4 and all(p.isdigit() for p in parts):
        return (0, *map(int, parts))
    return (1, ip)


def _label(p: Port) -> str:
    return f"{p.portid}/{p.protocol}"


def _analyze_host(host: Host, ex: HostExtras) -> list[Finding]:
    ip = host.address
    out: list[Finding] = []
    open_ports = [p for p in host.ports if p.state == "open"]

    def add(sev, title, detail, rec, ports, layer, source="nmap"):
        port_text = ", ".join(_label(p) for p in ports)
        out.append(Finding(sev, title, detail, rec, ip, port_text, layer, source))

    web_plain = []
    has_ssl = bool(ex.ssl_ports)
    smb_ports = []
    for p in open_ports:
        name = p.service.lower()
        is_ssl = (p.protocol, p.portid) in ex.ssl_ports

        # --- Cifrado (capa 6) ---
        tls = p.scripts.get("ssl-enum-ciphers", "")
        if "SSLv2" in tls or "SSLv3" in tls:
            add("critico", "Acepta SSL 2.0/3.0",
                "El servicio acepta versiones de SSL rotas desde hace años.",
                "Desactiva SSLv2 y SSLv3; deja solo TLS 1.2 y 1.3.", [p], 6, "ssl-enum-ciphers")
        elif "TLSv1.0" in tls or "TLSv1.1" in tls:
            add("alto", "Acepta TLS 1.0 / 1.1",
                "Permite versiones antiguas de TLS que un atacante en la red puede forzar.",
                "En la configuración del equipo deja solo TLS 1.2 y 1.3.", [p], 6, "ssl-enum-ciphers")

        if name.startswith("http") and not is_ssl:
            web_plain.append(p)

        # --- Sesión (capa 5) ---
        if p.portid in (139, 445) or name in ("microsoft-ds", "netbios-ssn"):
            smb_ports.append(p)
            if "SMBv1" in p.scripts.get("smb-protocols", ""):
                add("alto", "SMBv1 habilitado",
                    "SMBv1 es la versión usada por gusanos como WannaCry.",
                    "Desactiva SMBv1 en el equipo y usa SMB 2 o 3.", [p], 5, "smb-protocols")

        # --- Aplicación (capa 7) ---
        if p.portid == 23 or name == "telnet":
            add("alto", "Telnet abierto",
                "Telnet envía usuario y contraseña sin cifrar.",
                "Desactiva Telnet y usa SSH o el panel web con HTTPS.", [p], 7)
        elif p.portid == 21 or name == "ftp":
            add("medio", "FTP sin cifrar",
                "FTP transmite archivos y contraseñas en texto claro.",
                "Usa SFTP o FTPS, o desactiva el servicio si no lo necesitas.", [p], 7)
        elif p.portid == 3389 or name == "ms-wbt-server":
            add("medio", "Escritorio remoto (RDP) expuesto",
                "Cualquier equipo de la red puede intentar iniciar sesión por RDP.",
                "Desactívalo si no lo usas, o limítalo con el firewall y activa NLA.", [p], 7)
        elif 5900 <= p.portid <= 5903 or name.startswith("vnc"):
            add("alto", "VNC expuesto",
                "VNC permite controlar el equipo a distancia; muchas instalaciones usan claves débiles.",
                "Desactívalo o protégelo con contraseña fuerte y túnel SSH.", [p], 7)
        elif p.portid in DATABASE_PORTS:
            add("alto", f"Base de datos {DATABASE_PORTS[p.portid]} accesible",
                "La base de datos acepta conexiones desde la red.",
                "Haz que escuche solo en localhost o limita el acceso con el firewall.", [p], 7)
        elif p.portid == 554 or name == "rtsp":
            add("medio", "Video RTSP accesible",
                "El flujo de video de la cámara puede verse desde la red si no tiene contraseña.",
                "Activa la autenticación de RTSP y cambia la contraseña de fábrica.", [p], 7)
        elif (p.portid == 161 and p.protocol == "udp") or name == "snmp":
            add("medio", "SNMP expuesto",
                "SNMP con la comunidad 'public' revela la configuración del equipo.",
                "Desactiva SNMP o usa SNMPv3 con autenticación.", [p], 7)
        elif p.portid == 1900 or name == "upnp":
            add("bajo", "UPnP activo",
                "UPnP permite que los dispositivos abran puertos del router por su cuenta.",
                "Desactiva UPnP en el router si no lo necesitas.", [p], 7)
        elif p.portid == 9100 or name == "jetdirect":
            add("bajo", "Impresión directa abierta (9100)",
                "Cualquiera en la red puede enviar trabajos a la impresora.",
                "Limita el acceso por IP desde el panel de la impresora.", [p], 7)

    if web_plain:
        if has_ssl:
            add("bajo", "También responde por HTTP sin cifrar",
                "El equipo tiene HTTPS, pero sigue aceptando conexiones sin cifrar.",
                "Redirige HTTP a HTTPS o desactiva HTTP.", web_plain, 6)
        else:
            add("medio", "Panel web sin cifrar",
                "La página del equipo viaja sin cifrar: las contraseñas se pueden capturar.",
                "Activa HTTPS en el equipo o accede solo desde una red de confianza.", web_plain, 6)

    if smb_ports and not any(f.title == "SMBv1 habilitado" for f in out):
        add("bajo", "Carpetas compartidas (SMB) visibles",
            "El equipo comparte archivos en la red.",
            "Revisa qué carpetas compartes y que todas pidan contraseña.", smb_ports, 5)

    if len(open_ports) >= 15:
        add("bajo", "Muchos puertos abiertos",
            f"Tiene {len(open_ports)} puertos abiertos: más servicios, más puntos de entrada.",
            "Cierra los servicios que no uses.", [], 4)

    return out
