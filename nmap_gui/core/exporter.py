"""Exporta resultados de escaneo a TXT, XML, CSV y HTML."""

from __future__ import annotations

import csv
import html
import io
import time
from pathlib import Path

from .parser import ScanResult

FORMATS = {
    "txt": "Texto (*.txt)",
    "xml": "XML de nmap (*.xml)",
    "csv": "CSV (*.csv)",
    "html": "Informe HTML (*.html)",
}

CSV_HEADER = ["host", "hostname", "estado_host", "protocolo", "puerto", "estado", "servicio", "detalle"]


def to_csv(result: ScanResult) -> str:
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(CSV_HEADER)
    for host in result.hosts:
        hostname = host.hostnames[0] if host.hostnames else ""
        if not host.ports:
            writer.writerow([host.address, hostname, host.status, "", "", "", "", ""])
        for p in host.ports:
            writer.writerow(
                [host.address, hostname, host.status, p.protocol, p.portid, p.state, p.service, p.service_detail]
            )
    return buf.getvalue()


def to_html(result: ScanResult) -> str:
    e = html.escape
    started = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(result.start)) if result.start else ""
    parts = [
        "<!doctype html><html lang='es'><head><meta charset='utf-8'>",
        "<title>Informe nmap</title><style>",
        "body{font-family:system-ui,sans-serif;margin:2rem;color:#1f2933;background:#fff}",
        "h1{font-size:1.4rem}h2{font-size:1.1rem;margin-top:2rem}",
        "table{border-collapse:collapse;width:100%;margin-top:.5rem}",
        "th,td{border:1px solid #d9e2ec;padding:.35rem .6rem;text-align:left;font-size:.9rem}",
        "th{background:#f0f4f8}.open{color:#0a7c3f;font-weight:600}.closed{color:#b42318}",
        ".filtered{color:#a15c07}code{background:#f0f4f8;padding:.1rem .3rem;border-radius:3px}",
        "</style></head><body>",
        "<h1>Informe de escaneo nmap</h1>",
        f"<p>Comando: <code>{e(result.command)}</code></p>",
        f"<p>Inicio: {e(started)} · Duración: {result.elapsed:.1f} s · "
        f"Hosts activos: {result.hosts_up} · Inactivos: {result.hosts_down}</p>",
    ]
    for host in result.hosts:
        parts.append(f"<h2>{e(host.display_name)} — {e(host.status)}</h2>")
        extra = []
        if host.mac:
            extra.append(f"MAC: {e(host.mac)} {e(host.vendor)}")
        if host.best_os:
            extra.append(f"SO: {e(host.best_os)}")
        if extra:
            parts.append(f"<p>{' · '.join(extra)}</p>")
        if host.ports:
            parts.append("<table><tr><th>Puerto</th><th>Estado</th><th>Servicio</th><th>Detalle</th></tr>")
            for p in host.ports:
                cls = p.state.split("|")[0]
                parts.append(
                    f"<tr><td>{p.portid}/{e(p.protocol)}</td><td class='{e(cls)}'>{e(p.state)}</td>"
                    f"<td>{e(p.service)}</td><td>{e(p.service_detail)}</td></tr>"
                )
            parts.append("</table>")
    parts.append(f"<p><small>{e(result.summary)}</small></p></body></html>")
    return "\n".join(parts)


def export(path: str | Path, fmt: str, *, result: ScanResult | None, text_output: str, xml: str) -> None:
    """Escribe el escaneo en `path` con el formato indicado."""
    fmt = fmt.lower()
    if fmt == "txt":
        content = text_output
    elif fmt == "xml":
        content = xml
    elif fmt in ("csv", "html"):
        if result is None:
            raise ValueError("No hay resultados estructurados para exportar (el escaneo no generó XML).")
        content = to_csv(result) if fmt == "csv" else to_html(result)
    else:
        raise ValueError(f"Formato desconocido: {fmt}")
    Path(path).write_text(content, encoding="utf-8", newline="" if fmt == "csv" else None)
