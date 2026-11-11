"""Datos del XML de nmap que el parser de la versión 1 no guarda."""

from __future__ import annotations

import xml.etree.ElementTree as ET
from dataclasses import dataclass, field

SSL_SERVICES = {"https", "ssl", "imaps", "pop3s", "smtps", "ldaps", "ftps", "https-alt"}


@dataclass
class HostExtras:
    device_type: str = ""  # tipo según nmap: "printer", "webcam", "broadband router"…
    os_family: str = ""  # "Windows", "Linux", "embedded"…
    distance: int | None = None  # saltos de red hasta el equipo
    hops: list[str] = field(default_factory=list)  # IPs del traceroute, en orden
    reason: str = ""  # cómo se detectó: "arp-response", "echo-reply"…
    ssl_ports: set[tuple[str, int]] = field(default_factory=set)  # (protocolo, puerto) cifrados


def extract_extras(xml_text: str) -> dict[str, HostExtras]:
    """Devuelve los datos extra de cada host, indexados por su dirección IP."""
    if not xml_text.strip():
        return {}
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return {}

    extras: dict[str, HostExtras] = {}
    for host_el in root.findall("host"):
        address = ""
        for addr in host_el.findall("address"):
            if addr.get("addrtype") != "mac":
                address = addr.get("addr", "")
                break
        if not address:
            continue
        info = HostExtras()

        status = host_el.find("status")
        if status is not None:
            info.reason = status.get("reason", "")

        best = None
        for match in host_el.findall("os/osmatch"):
            acc = int(match.get("accuracy", "0") or 0)
            if best is None or acc > best[0]:
                best = (acc, match)
        if best is not None:
            cls = best[1].find("osclass")
            if cls is not None:
                info.device_type = cls.get("type", "")
                info.os_family = cls.get("osfamily", "")

        dist = host_el.find("distance")
        if dist is not None and dist.get("value", "").isdigit():
            info.distance = int(dist.get("value"))

        info.hops = [h.get("ipaddr", "") for h in host_el.findall("trace/hop") if h.get("ipaddr")]

        for port_el in host_el.findall("ports/port"):
            svc = port_el.find("service")
            if svc is None:
                continue
            name = svc.get("name", "")
            if svc.get("tunnel") == "ssl" or name in SSL_SERVICES or name.startswith("ssl"):
                info.ssl_ports.add((port_el.get("protocol", ""), int(port_el.get("portid", "0"))))

        extras[address] = info
    return extras
