"""Construye la lista de argumentos de nmap a partir de opciones de la interfaz.

Nunca se usa un shell: los argumentos se pasan como lista a QProcess, así que no
hay inyección de comandos. Aun así se validan los campos para evitar que un
objetivo se interprete como opción (por ejemplo "-oN /etc/passwd").
"""

from __future__ import annotations

import re
import shlex
from dataclasses import dataclass, replace

SCAN_TYPES: dict[str, str] = {
    "": "Predeterminado de nmap",
    "-sS": "TCP SYN (sigiloso, requiere admin)",
    "-sT": "TCP Connect",
    "-sU": "UDP (requiere admin)",
    "-sA": "TCP ACK (detectar firewalls)",
    "-sF": "TCP FIN",
    "-sN": "TCP Null",
    "-sX": "TCP Xmas",
    "-sn": "Solo descubrir hosts (sin puertos)",
}

TIMING_LABELS: dict[int, str] = {
    0: "T0 - Paranoico",
    1: "T1 - Sigiloso",
    2: "T2 - Educado",
    3: "T3 - Normal",
    4: "T4 - Agresivo",
    5: "T5 - Insano",
}

_TARGET_RE = re.compile(r"^[A-Za-z0-9.\-:/_\[\]*]+$")
_PORTS_RE = re.compile(r"^[0-9TUSP:,\-]+$")
_SCRIPTS_RE = re.compile(r"^[A-Za-z0-9_\-,.*/:]+$")
# Nosotros controlamos la salida (-oX) y no queremos que se pierda.
_FORBIDDEN_EXTRA = ("-o", "--resume", "--stylesheet", "--webxml")


class ValidationError(ValueError):
    """Error en los datos introducidos por el usuario."""


@dataclass
class ScanOptions:
    targets: str = ""
    scan_type: str = ""
    ports: str = ""
    top_ports: int | None = None
    fast: bool = False
    service_version: bool = False
    os_detection: bool = False
    aggressive: bool = False
    default_scripts: bool = False
    scripts: str = ""
    timing: int | None = None
    skip_ping: bool = False
    no_dns: bool = False
    verbose: bool = False
    open_only: bool = False
    ipv6: bool = False
    extra_args: str = ""


PROFILES: dict[str, ScanOptions] = {
    "Escaneo rápido": ScanOptions(fast=True, timing=4),
    "Escaneo normal": ScanOptions(),
    "Puertos y servicios": ScanOptions(service_version=True, timing=4),
    "Escaneo intenso": ScanOptions(aggressive=True, timing=4, verbose=True),
    "Descubrir hosts (ping)": ScanOptions(scan_type="-sn"),
    "Todos los puertos TCP": ScanOptions(ports="1-65535", timing=4),
    "UDP rápido": ScanOptions(scan_type="-sU", top_ports=100, timing=4),
    "Personalizado": ScanOptions(),
}


def apply_profile(name: str, targets: str = "") -> ScanOptions:
    """Devuelve una copia del perfil con los objetivos indicados."""
    return replace(PROFILES[name], targets=targets)


def parse_targets(text: str) -> list[str]:
    tokens = [t for t in re.split(r"[\s,]+", text.strip()) if t]
    if not tokens:
        raise ValidationError("Escribe al menos un objetivo (IP, rango o dominio).")
    for tok in tokens:
        if tok.startswith("-") or not _TARGET_RE.match(tok):
            raise ValidationError(f"Objetivo no válido: {tok!r}")
    return tokens


def parse_extra_args(text: str) -> list[str]:
    try:
        tokens = shlex.split(text)
    except ValueError as exc:
        raise ValidationError(f"Argumentos extra mal formados: {exc}") from exc
    for tok in tokens:
        if any(tok.startswith(bad) for bad in _FORBIDDEN_EXTRA):
            raise ValidationError(
                f"La opción {tok!r} no está permitida: la aplicación gestiona "
                "la salida del escaneo. Usa el menú Exportar."
            )
    return tokens


def build_args(opts: ScanOptions) -> list[str]:
    """Lista de argumentos para nmap (sin el ejecutable ni las opciones de salida)."""
    args: list[str] = []

    if opts.scan_type:
        if opts.scan_type not in SCAN_TYPES:
            raise ValidationError(f"Tipo de escaneo desconocido: {opts.scan_type}")
        args.append(opts.scan_type)

    port_scan = opts.scan_type != "-sn"
    if port_scan:
        if opts.ports.strip():
            ports = opts.ports.replace(" ", "")
            if not _PORTS_RE.match(ports):
                raise ValidationError(f"Puertos no válidos: {opts.ports!r}")
            args += ["-p", ports]
        elif opts.top_ports:
            if not 1 <= opts.top_ports <= 65535:
                raise ValidationError("--top-ports debe estar entre 1 y 65535.")
            args += ["--top-ports", str(opts.top_ports)]
        elif opts.fast:
            args.append("-F")

    if opts.aggressive:
        args.append("-A")
    else:
        if opts.service_version and port_scan:
            args.append("-sV")
        if opts.os_detection:
            args.append("-O")
        if opts.default_scripts:
            args.append("-sC")

    if opts.scripts.strip():
        scripts = opts.scripts.replace(" ", "")
        if not _SCRIPTS_RE.match(scripts):
            raise ValidationError(f"Scripts NSE no válidos: {opts.scripts!r}")
        args.append(f"--script={scripts}")

    if opts.timing is not None:
        if opts.timing not in TIMING_LABELS:
            raise ValidationError("La plantilla de tiempo debe ser T0–T5.")
        args.append(f"-T{opts.timing}")

    if opts.skip_ping:
        args.append("-Pn")
    if opts.no_dns:
        args.append("-n")
    if opts.verbose:
        args.append("-v")
    if opts.open_only:
        args.append("--open")
    if opts.ipv6:
        args.append("-6")

    args += parse_extra_args(opts.extra_args)
    args += parse_targets(opts.targets)
    return args


def display_command(args: list[str], executable: str = "nmap") -> str:
    """Comando legible para mostrar o copiar en una terminal."""
    return shlex.join([executable, *args])


def needs_privileges(args: list[str]) -> bool:
    """True si el escaneo normalmente requiere root/administrador."""
    privileged = {"-sS", "-sU", "-sA", "-sF", "-sN", "-sX", "-O", "-A"}
    return any(a in privileged for a in args)
