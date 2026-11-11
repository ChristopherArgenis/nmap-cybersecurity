"""Clasifica protocolos, herramientas y hallazgos según las 7 capas del modelo OSI."""

from __future__ import annotations

import re
from dataclasses import dataclass, field, replace

from nmap_gui.core.command_builder import ScanOptions
from nmap_gui.core.parser import ScanResult

from .extras import HostExtras
from .findings import Finding


@dataclass(frozen=True)
class Layer:
    number: int
    name: str
    subtitle: str
    explanation: str
    tools: tuple[str, ...]
    suggestion: ScanOptions
    suggestion_text: str


LAYERS: tuple[Layer, ...] = (
    Layer(7, "Aplicación", "Servicios que usas",
          "Es la capa de los programas: páginas web, SSH, DNS, impresión, cámaras. "
          "Aquí aparecen los servicios mal configurados o que no deberían estar abiertos.",
          ("nmap -sV", "scripts NSE"),
          ScanOptions(service_version=True, default_scripts=True, timing=4),
          "Detectar versiones y ejecutar los scripts por defecto (-sV -sC)"),
    Layer(6, "Presentación", "Cifrado y formato",
          "Aquí los datos se cifran antes de viajar (TLS). Si un equipo acepta versiones "
          "viejas o no cifra, alguien en la misma red podría leer lo que envías.",
          ("ssl-enum-ciphers", "ssl-cert"),
          ScanOptions(ports="443,465,636,993,995,8443", scripts="ssl-enum-ciphers,ssl-cert", timing=4),
          "Revisar versiones de TLS y certificados (ssl-enum-ciphers, ssl-cert)"),
    Layer(5, "Sesión", "Mantener conversaciones",
          "Organiza las conversaciones entre equipos: sesiones de archivos compartidos (SMB) "
          "o llamadas remotas (RPC).",
          ("smb-protocols", "smb-os-discovery"),
          ScanOptions(ports="135,139,445", scripts="smb-protocols,smb-os-discovery", timing=4),
          "Revisar versiones de SMB (smb-protocols, smb-os-discovery)"),
    Layer(4, "Transporte", "Puertos TCP y UDP",
          "Cada servicio escucha en un puerto TCP o UDP. Un puerto abierto es una puerta: "
          "cuantas menos haya abiertas, mejor.",
          ("nmap -sS / -sT", "nmap -sU"),
          ScanOptions(top_ports=1000, timing=4),
          "Escanear los 1000 puertos más comunes (--top-ports 1000)"),
    Layer(3, "Red", "Direcciones IP y rutas",
          "Las direcciones IP y los routers que llevan cada paquete a su destino. "
          "Aquí se ve quién está conectado y por dónde pasa el tráfico.",
          ("nmap -sn", "--traceroute"),
          ScanOptions(scan_type="-sn", extra_args="--traceroute"),
          "Descubrir equipos y rutas (-sn --traceroute)"),
    Layer(2, "Enlace", "MAC y switches",
          "Las direcciones MAC de cada tarjeta de red y los switches o puntos de acceso Wi‑Fi "
          "que las conectan dentro de la red local.",
          ("nmap -sn (ARP)", "tshark"),
          ScanOptions(scan_type="-sn"),
          "Inventario por ARP en la red local (-sn)"),
    Layer(1, "Física", "Cables y señal",
          "Los cables, la fibra y la señal de radio del Wi‑Fi. nmap no puede verla: "
          "se revisa a mano (quién puede conectar un cable o alcanzar tu Wi‑Fi).",
          ("Inspección física",),
          ScanOptions(),
          ""),
)

LAYER_BY_NUMBER = {layer.number: layer for layer in LAYERS}

_SESSION_SERVICES = {"netbios-ssn", "microsoft-ds", "msrpc", "rpcbind", "netbios-ns"}
_FRIENDLY = {
    "http": "HTTP", "http-proxy": "HTTP", "http-alt": "HTTP", "https": "HTTPS", "ssh": "SSH",
    "domain": "DNS", "telnet": "Telnet", "ftp": "FTP", "rtsp": "RTSP", "ipp": "IPP",
    "jetdirect": "JetDirect", "ms-wbt-server": "RDP", "upnp": "UPnP", "snmp": "SNMP",
    "smtp": "SMTP", "imap": "IMAP", "pop3": "POP3", "mysql": "MySQL", "vnc": "VNC",
    "netbios-ssn": "NetBIOS", "microsoft-ds": "SMB", "msrpc": "RPC", "rpcbind": "RPC",
}
_TLS_RE = re.compile(r"(SSLv[23]|TLSv1\.[0-3])")


@dataclass
class LayerSummary:
    layer: Layer
    protocols: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)


def build_osi(
    result: ScanResult | None,
    extras: dict[str, HostExtras],
    findings: list[Finding],
    host: str | None = None,
) -> list[LayerSummary]:
    """Resumen por capa (de la 7 a la 1). Con `host`, solo ese equipo."""
    summaries = {layer.number: LayerSummary(layer) for layer in LAYERS}
    if result is None:
        return list(summaries.values())

    hosts = [h for h in result.hosts if h.status == "up" and (host is None or h.address == host)]
    protos: dict[int, list[str]] = {n: [] for n in summaries}

    def note(layer: int, text: str) -> None:
        if text and text not in protos[layer]:
            protos[layer].append(text)

    tcp = udp = 0
    macs = 0
    for h in hosts:
        ex = extras.get(h.address, HostExtras())
        note(3, "IPv6" if ":" in h.address else "IPv4")
        if "echo" in ex.reason:
            note(3, "ICMP")
        if ex.hops:
            note(3, f"Rutas ({len(ex.hops)} saltos)")
        if h.mac:
            macs += 1
        if ex.reason == "arp-response":
            note(2, "ARP")
        for p in h.ports:
            if p.state != "open":
                continue
            if p.protocol == "udp":
                udp += 1
            else:
                tcp += 1
            name = p.service
            if name in _SESSION_SERVICES:
                note(5, _FRIENDLY.get(name, name))
                continue
            if name.startswith("http") and (p.protocol, p.portid) not in ex.ssl_ports:
                note(6, "HTTP sin cifrar")
            if (p.protocol, p.portid) in ex.ssl_ports:
                versions = _TLS_RE.findall(p.scripts.get("ssl-enum-ciphers", ""))
                for v in versions or ["TLS"]:
                    note(6, v.replace("v", " "))
            if name:
                label = _FRIENDLY.get(name, name.upper())
                if (p.protocol, p.portid) in ex.ssl_ports and label == "HTTP":
                    label = "HTTPS"
                note(7, label)
    if tcp:
        note(4, f"TCP · {tcp} abiertos")
    if udp:
        note(4, f"UDP · {udp} abiertos")
    if macs:
        note(2, f"MAC · {macs} equipo{'s' if macs != 1 else ''}")

    for n, s in summaries.items():
        s.protocols = protos[n]
    for f in findings:
        if host is None or f.host == host:
            summaries[f.layer].findings.append(f)
    return list(summaries.values())


def suggested_options(layer_number: int, targets: str) -> ScanOptions:
    """Escaneo recomendado para investigar una capa sobre los objetivos dados."""
    return replace(LAYER_BY_NUMBER[layer_number].suggestion, targets=targets)
