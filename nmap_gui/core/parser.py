"""Convierte la salida XML de nmap (-oX) en objetos de Python."""

from __future__ import annotations

import xml.etree.ElementTree as ET
from dataclasses import dataclass, field


@dataclass
class Port:
    protocol: str
    portid: int
    state: str
    reason: str = ""
    service: str = ""
    product: str = ""
    version: str = ""
    extrainfo: str = ""
    scripts: dict[str, str] = field(default_factory=dict)

    @property
    def service_detail(self) -> str:
        return " ".join(p for p in (self.product, self.version, self.extrainfo) if p)


@dataclass
class Host:
    address: str
    status: str = "unknown"
    addr_type: str = ""
    mac: str = ""
    vendor: str = ""
    hostnames: list[str] = field(default_factory=list)
    os_matches: list[tuple[str, int]] = field(default_factory=list)
    ports: list[Port] = field(default_factory=list)

    @property
    def display_name(self) -> str:
        if self.hostnames:
            return f"{self.address} ({self.hostnames[0]})"
        return self.address

    @property
    def best_os(self) -> str:
        if not self.os_matches:
            return ""
        name, accuracy = self.os_matches[0]
        return f"{name} ({accuracy}%)"

    @property
    def open_ports(self) -> list[Port]:
        return [p for p in self.ports if p.state == "open"]


@dataclass
class ScanResult:
    command: str = ""
    start: int = 0
    elapsed: float = 0.0
    summary: str = ""
    hosts_up: int = 0
    hosts_down: int = 0
    hosts: list[Host] = field(default_factory=list)


def parse_xml(xml_text: str) -> ScanResult:
    """Analiza el XML de nmap. Lanza ValueError si no es XML válido de nmap."""
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        raise ValueError(f"XML de nmap no válido: {exc}") from exc
    if root.tag != "nmaprun":
        raise ValueError("El archivo no es una salida XML de nmap.")

    result = ScanResult(
        command=root.get("args", ""),
        start=int(root.get("start", "0") or 0),
    )

    for host_el in root.findall("host"):
        result.hosts.append(_parse_host(host_el))

    finished = root.find("runstats/finished")
    if finished is not None:
        result.elapsed = float(finished.get("elapsed", "0") or 0)
        result.summary = finished.get("summary", "")
    hosts_el = root.find("runstats/hosts")
    if hosts_el is not None:
        result.hosts_up = int(hosts_el.get("up", "0"))
        result.hosts_down = int(hosts_el.get("down", "0"))
    return result


def _parse_host(el: ET.Element) -> Host:
    status_el = el.find("status")
    host = Host(address="", status=status_el.get("state", "") if status_el is not None else "")

    for addr in el.findall("address"):
        kind = addr.get("addrtype", "")
        if kind == "mac":
            host.mac = addr.get("addr", "")
            host.vendor = addr.get("vendor", "")
        elif not host.address:
            host.address = addr.get("addr", "")
            host.addr_type = kind

    host.hostnames = [h.get("name", "") for h in el.findall("hostnames/hostname") if h.get("name")]

    for match in el.findall("os/osmatch"):
        host.os_matches.append((match.get("name", ""), int(match.get("accuracy", "0") or 0)))

    for port_el in el.findall("ports/port"):
        state_el = port_el.find("state")
        svc = port_el.find("service")
        port = Port(
            protocol=port_el.get("protocol", ""),
            portid=int(port_el.get("portid", "0")),
            state=state_el.get("state", "") if state_el is not None else "",
            reason=state_el.get("reason", "") if state_el is not None else "",
        )
        if svc is not None:
            port.service = svc.get("name", "")
            port.product = svc.get("product", "")
            port.version = svc.get("version", "")
            port.extrainfo = svc.get("extrainfo", "")
        for script in port_el.findall("script"):
            port.scripts[script.get("id", "")] = script.get("output", "")
        host.ports.append(port)

    return host
