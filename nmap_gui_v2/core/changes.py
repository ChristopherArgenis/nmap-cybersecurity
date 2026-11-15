"""Vigilancia de cambios: compara dos escaneos de la misma red (como ndiff)."""

from __future__ import annotations

from dataclasses import dataclass, field

from nmap_gui.core.parser import Host, ScanResult

from .findings import DATABASE_PORTS

# Puertos que conviene vigilar especialmente si aparecen abiertos de repente.
RISKY_PORTS = {21, 23, 445, 3389, 5900, 5901, 5902, 5903, 161, *DATABASE_PORTS}

CHANGE_LABELS = {
    "host_nuevo": "Equipo nuevo",
    "host_desaparecido": "Equipo que ya no responde",
    "puerto_abierto": "Puerto abierto nuevo",
    "puerto_cerrado": "Puerto que se cerró",
    "servicio_cambiado": "Servicio cambiado",
    "so_cambiado": "Sistema operativo distinto",
}

# "info" = cambio neutro o positivo (por ejemplo, un puerto que se cerró).
CHANGE_SEVERITIES = ("alto", "medio", "bajo", "info")


@dataclass(frozen=True)
class Change:
    kind: str
    severity: str
    host: str
    title: str
    detail: str
    port: str = ""

    @property
    def label(self) -> str:
        return CHANGE_LABELS[self.kind]


@dataclass
class ChangeSet:
    before_label: str = ""
    after_label: str = ""
    changes: list[Change] = field(default_factory=list)

    @property
    def empty(self) -> bool:
        return not self.changes

    def of_kind(self, kind: str) -> list[Change]:
        return [c for c in self.changes if c.kind == kind]

    @property
    def new_hosts(self) -> set[str]:
        return {c.host for c in self.of_kind("host_nuevo")}

    @property
    def opened(self) -> dict[str, list[str]]:
        out: dict[str, list[str]] = {}
        for c in self.of_kind("puerto_abierto"):
            out.setdefault(c.host, []).append(c.port)
        return out

    def for_host(self, ip: str) -> list[Change]:
        return [c for c in self.changes if c.host == ip]


def _host_name(h: Host) -> str:
    return f"{h.address} ({h.hostnames[0]})" if h.hostnames else h.address


def _open_ports(h: Host) -> dict[str, object]:
    return {f"{p.portid}/{p.protocol}": p for p in h.ports if p.state == "open"}


def compare(before: ScanResult | None, after: ScanResult | None,
            before_label: str = "Escaneo anterior", after_label: str = "Escaneo actual") -> ChangeSet:
    """Diferencias entre dos escaneos. Solo cuenta equipos activos."""
    cs = ChangeSet(before_label, after_label)
    if before is None or after is None:
        return cs
    old = {h.address: h for h in before.hosts if h.status == "up"}
    new = {h.address: h for h in after.hosts if h.status == "up"}

    for ip in sorted(new.keys() - old.keys(), key=_ip_key):
        h = new[ip]
        ports = ", ".join(_open_ports(h)) or "ninguno visible"
        who = " ".join(x for x in (h.vendor, h.best_os) if x) or "fabricante desconocido"
        cs.changes.append(Change(
            "host_nuevo", "medio", ip, f"Equipo nuevo: {_host_name(h)}",
            f"No estaba en el escaneo anterior ({who}). Puertos abiertos: {ports}. "
            "Comprueba que sea un equipo tuyo."))

    for ip in sorted(old.keys() - new.keys(), key=_ip_key):
        cs.changes.append(Change(
            "host_desaparecido", "info", ip, f"Ya no responde: {_host_name(old[ip])}",
            "Estaba en el escaneo anterior. Puede estar apagado o desconectado."))

    for ip in sorted(old.keys() & new.keys(), key=_ip_key):
        a, b = old[ip], new[ip]
        pa, pb = _open_ports(a), _open_ports(b)
        for port in sorted(pb.keys() - pa.keys(), key=_port_key):
            p = pb[port]
            risky = p.portid in RISKY_PORTS or p.service in ("telnet", "ftp", "ms-wbt-server", "vnc")
            svc = " ".join(x for x in (p.service, p.service_detail) if x) or "servicio desconocido"
            cs.changes.append(Change(
                "puerto_abierto", "alto" if risky else "medio", ip,
                f"Se abrió el puerto {port} en {_host_name(b)}",
                f"Servicio: {svc}. Si no lo activaste tú, revisa el equipo.", port))
        for port in sorted(pa.keys() - pb.keys(), key=_port_key):
            cs.changes.append(Change(
                "puerto_cerrado", "info", ip, f"Se cerró el puerto {port} en {_host_name(b)}",
                "Ya no responde como abierto.", port))
        for port in sorted(pa.keys() & pb.keys(), key=_port_key):
            x, y = pa[port], pb[port]
            before_svc = " ".join(v for v in (x.service, x.service_detail) if v)
            after_svc = " ".join(v for v in (y.service, y.service_detail) if v)
            if before_svc and after_svc and before_svc != after_svc:
                cs.changes.append(Change(
                    "servicio_cambiado", "bajo", ip, f"Cambió el servicio en {port} de {_host_name(b)}",
                    f"Antes: {before_svc}. Ahora: {after_svc}.", port))
        if a.best_os and b.best_os and a.os_matches[0][0] != b.os_matches[0][0]:
            cs.changes.append(Change(
                "so_cambiado", "bajo", ip, f"Sistema distinto en {_host_name(b)}",
                f"Antes: {a.best_os}. Ahora: {b.best_os}. Puede ser una actualización o la detección."))

    order = {s: i for i, s in enumerate(CHANGE_SEVERITIES)}
    cs.changes.sort(key=lambda c: (order[c.severity], _ip_key(c.host), _port_key(c.port)))
    return cs


def _ip_key(ip: str) -> tuple:
    parts = ip.split(".")
    if len(parts) == 4 and all(p.isdigit() for p in parts):
        return (0, *map(int, parts))
    return (1, ip)


def _port_key(port: str) -> tuple:
    num, _, proto = port.partition("/")
    return (proto, int(num)) if num.isdigit() else ("", 0)
