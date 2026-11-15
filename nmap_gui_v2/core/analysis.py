"""Une todo el análisis de un escaneo: datos extra, hallazgos y topología."""

from __future__ import annotations

from dataclasses import dataclass, field

from nmap_gui.core.parser import ScanResult

from .changes import ChangeSet, compare
from .extras import HostExtras, extract_extras
from .findings import Finding, analyze
from .topology import Topology, build_topology


@dataclass
class Analysis:
    result: ScanResult | None = None
    extras: dict[str, HostExtras] = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)
    topology: Topology = field(default_factory=Topology)
    changes: ChangeSet = field(default_factory=ChangeSet)


def analyze_scan(
    result: ScanResult | None,
    xml: str,
    previous: ScanResult | None = None,
    previous_label: str = "Escaneo anterior",
    current_label: str = "Escaneo actual",
) -> Analysis:
    """Analiza un escaneo. Con `previous`, también marca lo que cambió desde entonces."""
    extras = extract_extras(xml)
    findings = analyze(result, extras)
    topology = build_topology(result, extras, findings)
    changes = compare(previous, result, previous_label, current_label)
    new_hosts, opened = changes.new_hosts, changes.opened
    for node in topology.nodes:
        if node.id in new_hosts:
            node.change = "nuevo"
        elif node.id in opened:
            node.change = f"+{len(opened[node.id])} puerto" + ("s" if len(opened[node.id]) > 1 else "")
    return Analysis(result, extras, findings, topology, changes)
