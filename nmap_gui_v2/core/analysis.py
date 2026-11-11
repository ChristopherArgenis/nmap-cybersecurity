"""Une todo el análisis de un escaneo: datos extra, hallazgos y topología."""

from __future__ import annotations

from dataclasses import dataclass, field

from nmap_gui.core.parser import ScanResult

from .extras import HostExtras, extract_extras
from .findings import Finding, analyze
from .topology import Topology, build_topology


@dataclass
class Analysis:
    result: ScanResult | None = None
    extras: dict[str, HostExtras] = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)
    topology: Topology = field(default_factory=Topology)


def analyze_scan(result: ScanResult | None, xml: str) -> Analysis:
    extras = extract_extras(xml)
    findings = analyze(result, extras)
    return Analysis(result, extras, findings, build_topology(result, extras, findings))
