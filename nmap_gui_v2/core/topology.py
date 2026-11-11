"""Construye un mapa de la red (nodos y conexiones) a partir de un escaneo.

nmap no ve los cables: el mapa es una deducción. Los equipos a un salto se
dibujan en la red local detrás de la puerta de enlace; los que están más lejos
se conectan siguiendo los saltos de --traceroute cuando existen.
"""

from __future__ import annotations

import ipaddress
from collections import Counter
from dataclasses import dataclass, field

from nmap_gui.core.parser import Host, ScanResult

from .extras import HostExtras
from .findings import Finding, worst

KIND_LABELS = {
    "internet": "Internet",
    "hub": "Red local",
    "hop": "Salto de red",
    "gateway": "Router",
    "network": "Equipo de red",
    "computer": "Computadora",
    "server": "Servidor",
    "storage": "Almacenamiento (NAS)",
    "camera": "Cámara IP",
    "printer": "Impresora",
    "phone": "Teléfono",
    "media": "Multimedia",
    "iot": "Dispositivo IoT",
    "unknown": "Equipo desconocido",
}

ZONE_LABELS = {
    "infra": "Infraestructura",
    "equipos": "Equipos",
    "iot": "IoT y dispositivos",
    "remotos": "Fuera de la red local",
}

_ZONE_BY_KIND = {
    "internet": "infra",
    "hub": "infra",
    "hop": "remotos",
    "gateway": "infra",
    "network": "infra",
    "computer": "equipos",
    "server": "equipos",
    "storage": "equipos",
    "unknown": "equipos",
    "camera": "iot",
    "printer": "iot",
    "phone": "iot",
    "media": "iot",
    "iot": "iot",
}

_TYPE_TO_KIND = {
    "router": "gateway",
    "broadband router": "gateway",
    "firewall": "gateway",
    "wap": "network",
    "switch": "network",
    "bridge": "network",
    "load balancer": "network",
    "webcam": "camera",
    "printer": "printer",
    "print server": "printer",
    "phone": "phone",
    "media device": "media",
    "game console": "media",
    "storage-misc": "storage",
    "specialized": "iot",
    "power-device": "iot",
    "terminal": "iot",
    "pbx": "iot",
    "security-misc": "iot",
}

_VENDOR_HINTS = (
    (("hikvision", "dahua", "axis", "reolink", "wyze"), "camera"),
    (("synology", "qnap", "western digital"), "storage"),
    (("brother", "epson", "canon", "lexmark", "xerox"), "printer"),
    (("tp-link", "netgear", "ubiquiti", "mikrotik", "cisco", "huawei", "arris", "technicolor"), "network"),
    (("sonos", "roku", "samsung electronics", "lg electronics", "sony", "nintendo"), "media"),
    (("espressif", "tuya", "shelly", "amazon technologies", "google"), "iot"),
)

_SERVER_PORTS = {22, 25, 53, 80, 110, 143, 443, 3306, 5432, 8080, 8443}


@dataclass
class Node:
    id: str
    kind: str
    label: str
    sublabel: str
    zone: str
    ip: str = ""
    risk: str = ""  # peor severidad de sus hallazgos, o ""
    findings: int = 0
    host: Host | None = None

    @property
    def kind_label(self) -> str:
        return KIND_LABELS.get(self.kind, self.kind)


@dataclass(frozen=True)
class Edge:
    a: str
    b: str


@dataclass
class Topology:
    nodes: list[Node] = field(default_factory=list)
    edges: list[Edge] = field(default_factory=list)
    subnet: str = ""

    def node(self, node_id: str) -> Node | None:
        return next((n for n in self.nodes if n.id == node_id), None)

    def by_zone(self, zone: str) -> list[Node]:
        return [n for n in self.nodes if n.zone == zone]


def classify(host: Host, ex: HostExtras) -> str:
    """Tipo de equipo, según lo que nmap dedujo, el fabricante y los puertos."""
    dtype = ex.device_type.lower()
    if dtype in _TYPE_TO_KIND:
        return _TYPE_TO_KIND[dtype]

    ports = {p.portid for p in host.ports if p.state == "open"}
    services = {p.service for p in host.ports if p.state == "open"}
    vendor = host.vendor.lower()

    if ports & {9100, 631, 515} or "ipp" in services or "jetdirect" in services:
        return "printer"
    if 554 in ports or "rtsp" in services:
        return "camera"
    if 62078 in ports:
        return "phone"
    for keywords, kind in _VENDOR_HINTS:
        if any(k in vendor for k in keywords):
            return kind
    if dtype == "general purpose":
        family = ex.os_family.lower()
        if family == "windows":
            return "computer"
        if ports & _SERVER_PORTS:
            return "server"
        return "computer"
    if not ports:
        return "unknown"
    if ports & _SERVER_PORTS:
        return "server"
    return "unknown"


def _subnet(ips: list[str]) -> str:
    nets = []
    for ip in ips:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            continue
        if addr.version == 4:
            nets.append(str(ipaddress.ip_network(f"{ip}/24", strict=False)))
    return Counter(nets).most_common(1)[0][0] if nets else ""


def build_topology(
    result: ScanResult | None, extras: dict[str, HostExtras], findings: list[Finding]
) -> Topology:
    topo = Topology()
    if result is None:
        return topo
    up = [h for h in result.hosts if h.status == "up" and h.address]
    by_host: dict[str, list[Finding]] = {}
    for f in findings:
        by_host.setdefault(f.host, []).append(f)

    def is_remote(h: Host) -> bool:
        ex = extras.get(h.address)
        return bool(ex and ex.distance and ex.distance > 1)

    local = [h for h in up if not is_remote(h)]
    remote = [h for h in up if is_remote(h)]
    topo.subnet = _subnet([h.address for h in local])
    kinds = {h.address: classify(h, extras.get(h.address, HostExtras())) for h in up}

    # Puerta de enlace: un router detectado, el primer salto de un traceroute
    # o, si no hay más pistas, la .1 / .254 de la red local.
    gateway = None
    routers = sorted((h for h in local if kinds[h.address] == "gateway"), key=lambda h: h.address)
    if routers:
        gateway = routers[0]
    else:
        first_hops = {extras[h.address].hops[0] for h in remote if extras[h.address].hops}
        gateway = next((h for h in local if h.address in first_hops), None)
        if gateway is None:
            gateway = next((h for h in local if h.address.rsplit(".", 1)[-1] in ("1", "254")), None)
    if gateway is not None:
        kinds[gateway.address] = "gateway"

    def add_host(h: Host, zone: str | None = None) -> Node:
        hf = by_host.get(h.address, [])
        kind = kinds[h.address]
        if h.hostnames:
            name = h.hostnames[0].split(".")[0]
        elif kind == "unknown" and h.vendor:
            name = h.vendor.split()[0]
        else:
            name = KIND_LABELS[kind]
        node = Node(
            id=h.address,
            kind=kind,
            label=name,
            sublabel=h.address,
            zone=zone or _ZONE_BY_KIND[kind],
            ip=h.address,
            risk=worst(hf),
            findings=len(hf),
            host=h,
        )
        topo.nodes.append(node)
        return node

    hub_id = "hub"
    if local:
        topo.nodes.append(Node(hub_id, "hub", "Red local", topo.subnet or "LAN", "infra"))
    if gateway is not None:
        topo.nodes.append(Node("internet", "internet", "Internet", "", "infra"))
        add_host(gateway, "infra")
        topo.edges.append(Edge("internet", gateway.address))
        topo.edges.append(Edge(gateway.address, hub_id))

    for h in sorted(local, key=lambda h: _ip_sort(h.address)):
        if h is gateway:
            continue
        add_host(h)
        topo.edges.append(Edge(hub_id, h.address))

    scanned = {h.address for h in up}
    for h in sorted(remote, key=lambda h: _ip_sort(h.address)):
        add_host(h, "remotos")
        hops = [ip for ip in extras[h.address].hops if ip != h.address]
        prev = gateway.address if gateway is not None else ("internet" if topo.node("internet") else hub_id)
        if hops and gateway is not None and hops[0] == gateway.address:
            hops = hops[1:]
        if not topo.node(prev):
            topo.nodes.append(Node("internet", "internet", "Internet", "", "infra"))
            prev = "internet"
        for ip in hops:
            hop_id = ip if ip in scanned else f"hop:{ip}"
            if not topo.node(hop_id):
                topo.nodes.append(Node(hop_id, "hop", "Salto", ip, "remotos", ip=ip))
            if Edge(prev, hop_id) not in topo.edges:
                topo.edges.append(Edge(prev, hop_id))
            prev = hop_id
        topo.edges.append(Edge(prev, h.address))

    return topo


def _ip_sort(ip: str) -> tuple:
    try:
        return (0, int(ipaddress.ip_address(ip)))
    except ValueError:
        return (1, ip)


# ----------------------------------------------------------------- diseño
NODE_W, NODE_H = 172, 64
_COL, _ROW, _PER_ROW = 196, 112, 6


@dataclass
class Layout:
    positions: dict[str, tuple[float, float]] = field(default_factory=dict)  # centro de cada nodo
    zones: dict[str, tuple[float, float, float, float]] = field(default_factory=dict)  # x, y, ancho, alto


def layout(topo: Topology) -> Layout:
    """Coloca los nodos por niveles: Internet, router, red local y luego cada zona."""
    out = Layout()
    y = 0.0

    def place_row(nodes: list[Node], y: float, cx: float = 0.0, per_row: int = _PER_ROW) -> float:
        rows = [nodes[i:i + per_row] for i in range(0, len(nodes), per_row)]
        for row in rows:
            width = (len(row) - 1) * _COL
            for i, n in enumerate(row):
                out.positions[n.id] = (cx - width / 2 + i * _COL, y)
            y += _ROW
        return y

    for kind in ("internet", "gateway", "hub"):
        nodes = [n for n in topo.nodes if n.kind == kind and n.zone == "infra"]
        if nodes:
            y = place_row(nodes, y)
    infra_net = [n for n in topo.nodes if n.kind == "network"]
    if infra_net:
        y = place_row(infra_net, y)

    y += 24
    for zone in ("equipos", "iot"):
        nodes = topo.by_zone(zone)
        if not nodes:
            continue
        top = y
        y = place_row(nodes, y + 18)
        w = (min(len(nodes), _PER_ROW) - 1) * _COL + NODE_W + 48
        out.zones[zone] = (-w / 2, top - NODE_H / 2 - 14, w, y - top + 6)
        y += 40

    # Lo que está fuera de la red local va a la derecha, para que sus líneas
    # no crucen la red local.
    groups = [[n for n in topo.by_zone("remotos") if n.kind == "hop"],
              [n for n in topo.by_zone("remotos") if n.kind != "hop"]]
    groups = [g for g in groups if g]
    if groups:
        per_row = 3
        widest = max(min(len(g), per_row) for g in groups)
        w = (widest - 1) * _COL + NODE_W + 48
        right = max((abs(x) for x, _ in out.positions.values()), default=0) + NODE_W / 2
        for zx, _zy, zw, _zh in out.zones.values():
            right = max(right, zx + zw)
        cx = right + 80 + w / 2
        top = _ROW if any(n.kind == "gateway" for n in topo.nodes) else 0.0
        ry = top
        for g in groups:
            ry = place_row(g, ry + 18, cx, per_row)
        out.zones["remotos"] = (cx - w / 2, top - NODE_H / 2 - 14, w, ry - top + 6)
    return out
