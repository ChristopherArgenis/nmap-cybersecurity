"""Contenido del reporte PDF: un documento HTML que Qt convierte en PDF.

Usa solo el HTML/CSS que entiende QTextDocument (tablas, colores, saltos de
página). Todo el texto que viene del escaneo se escapa.
"""

from __future__ import annotations

import html
import time
from collections import Counter
from dataclasses import dataclass

from .analysis import Analysis
from .findings import SEVERITIES, SEVERITY_LABELS, SEVERITY_RANK, worst
from .osi import LAYERS
from .topology import KIND_LABELS
from .webaudit import WebResult

MAP_IMAGE = "mapa.png"  # nombre del recurso de imagen dentro del documento

# Colores pensados para papel (texto oscuro, buen contraste).
INK, MUTED, LINE, SOFT = "#1f2933", "#52606d", "#d9e2ec", "#f5f7fa"
SEV_COLOR = {"critico": "#a61b1b", "alto": "#c62828", "medio": "#b45309", "bajo": "#1d5fa8", "info": "#2f7d4f"}
STATUS_TEXT = {
    "critico": "Crítico: hay problemas graves que conviene corregir hoy.",
    "alto": "Requiere atención: hay problemas importantes que corregir pronto.",
    "medio": "Aceptable con mejoras: hay puntos a corregir sin urgencia extrema.",
    "bajo": "Bueno: solo detalles menores.",
    "": "Muy bueno: no se detectaron problemas con las reglas de esta herramienta.",
}


@dataclass
class ReportMeta:
    title: str = "Informe de seguridad de la red"
    author: str = ""
    scope: str = ""  # objetivos escaneados
    command: str = ""
    generated_at: float = 0.0
    demo: bool = False
    app_version: str = ""
    include_map: bool = True


def _e(text) -> str:
    return html.escape(str(text or ""))


def _nowrap(text) -> str:
    # Las IP no se parten en dos líneas: los puntos se unen con espacios no separables.
    return _e(text).replace(".", ".\u2060")


def _sev(sev: str) -> str:
    label = SEVERITY_LABELS.get(sev, "Info") if sev != "info" else "Bien / neutro"
    return f"<span style='color:{SEV_COLOR.get(sev, MUTED)}; font-weight:bold'>{_e(label)}</span>"


def _table(headers: list[str], rows: list[list[str]], widths: list[int] | None = None) -> str:
    out = [f"<table width='100%' cellspacing='0' cellpadding='5' style='border-collapse:collapse; "
           f"border:1px solid {LINE}; margin-top:6px'>",
           f"<tr style='background-color:{SOFT}'>"]
    for i, h in enumerate(headers):
        w = f" width='{widths[i]}%'" if widths else ""
        out.append(f"<th align='left'{w} style='color:{MUTED}; font-size:7pt'>{_e(h).upper()}</th>")
    out.append("</tr>")
    for row in rows:
        out.append("<tr>" + "".join(f"<td valign='top' style='border-top:1px solid {LINE}; font-size:8.5pt'>{c}</td>"
                                     for c in row) + "</tr>")
    out.append("</table>")
    return "".join(out)


def build_report_html(analysis: Analysis, web_results: list[WebResult], meta: ReportMeta) -> str:
    result = analysis.result
    findings = analysis.findings
    hosts = [h for h in result.hosts if h.status == "up"] if result else []
    when = time.strftime("%d/%m/%Y %H:%M", time.localtime(meta.generated_at or time.time()))
    counts = Counter(f.severity for f in findings)
    status = worst(findings)
    open_ports = sum(len(h.open_ports) for h in hosts)
    p: list[str] = [f"<html><body style='color:{INK}'>"]

    # ---------------------------------------------------------- portada
    p.append(f"<p style='color:{SEV_COLOR['info']}; font-size:9pt; font-weight:bold'>NMAP STUDIO · REPORTE</p>")
    p.append(f"<h1 style='font-size:24pt; margin-bottom:4px'>{_e(meta.title)}</h1>")
    if meta.demo:
        p.append(f"<p style='color:{SEV_COLOR['alto']}; font-weight:bold'>DATOS DE EJEMPLO · red ficticia "
                 "incluida en la app; no corresponde a ninguna red real.</p>")
    info = [["Red o equipos revisados", _e(meta.scope or "—")], ["Fecha", _e(when)]]
    if meta.author:
        info.insert(0, ["Elaborado por", _e(meta.author)])
    p.append(_table(["Dato", "Valor"], info, [35, 65]))

    # -------------------------------------------------- resumen ejecutivo
    p.append("<h2>1. Resumen ejecutivo</h2>")
    color = SEV_COLOR.get(status, SEV_COLOR["info"])
    p.append(f"<p style='font-size:12pt'><b>Estado general:</b> "
             f"<span style='color:{color}; font-weight:bold'>{_e(STATUS_TEXT[status])}</span></p>")
    p.append(_table(
        ["Equipos activos", "Puertos abiertos", "Hallazgos", "Cambios desde el escaneo anterior"],
        [[f"<b style='font-size:14pt'>{len(hosts)}</b>", f"<b style='font-size:14pt'>{open_ports}</b>",
          f"<b style='font-size:14pt'>{len(findings)}</b>",
          f"<b style='font-size:14pt'>{len(analysis.changes.changes)}</b>"]]))
    p.append(_table(["Severidad", "Cantidad"],
                    [[_sev(s), str(counts.get(s, 0))] for s in SEVERITIES], [70, 30]))
    top = findings[:5]
    if top:
        p.append("<h3>Prioridades</h3><ol>")
        for f in top:
            p.append(f"<li>{_sev(f.severity)} · <b>{_e(f.title)}</b> en {_e(f.host)}"
                     f"{' (' + _e(f.port) + ')' if f.port else ''}.<br>"
                     f"<span style='color:{MUTED}'>Qué hacer: {_e(f.recommendation)}</span></li>")
        p.append("</ol>")

    # --------------------------------------------------------------- mapa
    if meta.include_map and analysis.topology.nodes:
        p.append("<h2 style='page-break-before:always'>2. Mapa de la red</h2>")
        p.append(f"<p style='color:{MUTED}'>Deducido del escaneo: nmap no ve los cables. Borde rojo = riesgo alto, "
                 "ámbar = medio, azul = bajo; etiqueta azul = equipo nuevo o con puertos nuevos.</p>")
        p.append(f"<p align='center'><img src='{MAP_IMAGE}' width='540'></p>")

    # ------------------------------------------------------------ equipos
    p.append("<h2>3. Equipos encontrados</h2>")
    by_id = {n.id: n for n in analysis.topology.nodes}
    rows = []
    for h in hosts:
        node = by_id.get(h.address)
        kind = KIND_LABELS.get(node.kind, "") if node else ""
        ports = ", ".join(f"{pt.portid}/{pt.protocol} {pt.service}".strip() for pt in h.open_ports) or "—"
        risk = _sev(node.risk) if node and node.risk else "—"
        name = _e(h.hostnames[0]) if h.hostnames else _e(h.vendor or "")
        rows.append([f"<b>{_nowrap(h.address)}</b><br><span style='color:{MUTED}'>{name}</span>",
                     _e(kind), _e(h.best_os or "—"), _e(ports), risk])
    p.append(_table(["Equipo", "Tipo", "Sistema", "Puertos abiertos", "Riesgo"], rows, [22, 16, 21, 29, 12])
             if rows else "<p>No se encontraron equipos activos.</p>")

    # ------------------------------------------------ hallazgos por capa
    p.append("<h2>4. Hallazgos por capa del modelo OSI</h2>")
    p.append(f"<p style='color:{MUTED}'>Cada hallazgo se ubica en la capa donde ocurre. Las severidades son "
             "orientativas: indican qué revisar primero.</p>")
    any_layer = False
    for layer in LAYERS:
        items = [f for f in findings if f.layer == layer.number]
        if not items:
            continue
        any_layer = True
        p.append(f"<h3>Capa {layer.number} · {_e(layer.name)} <span style='color:{MUTED}; font-weight:normal'>"
                 f"({_e(layer.subtitle.lower())})</span></h3>")
        p.append(_table(
            ["Severidad", "Equipo", "Hallazgo", "Qué hacer"],
            [[_sev(f.severity), f"{_nowrap(f.host)}<br><span style='color:{MUTED}'>{_e(f.port)}</span>",
              f"<b>{_e(f.title)}</b><br><span style='color:{MUTED}'>{_e(f.detail)}</span>"
              f"<br><span style='color:{MUTED}; font-size:8pt'>Fuente: {_e(f.source)}</span>",
              _e(f.recommendation)] for f in sorted(items, key=lambda f: SEVERITY_RANK[f.severity])],
            [15, 19, 36, 30]))
    if not any_layer:
        p.append("<p>No se detectaron hallazgos.</p>")

    # ------------------------------------------------------------ cambios
    cs = analysis.changes
    if cs.before_label:
        p.append("<h2>5. Cambios desde el escaneo anterior</h2>")
        p.append(f"<p style='color:{MUTED}'>{_e(cs.before_label)} → {_e(cs.after_label)}</p>")
        if cs.empty:
            p.append("<p>Sin cambios: la red se ve igual que en el escaneo anterior.</p>")
        else:
            p.append(_table(["Importancia", "Cambio", "Detalle"],
                            [[_sev(c.severity), f"<b>{_e(c.title)}</b>", _e(c.detail)] for c in cs.changes],
                            [18, 33, 49]))

    # ------------------------------------------------------ auditoría web
    if web_results:
        p.append("<h2>6. Auditoría web y TLS</h2>")
        if any(r.example for r in web_results):
            p.append(f"<p style='color:{SEV_COLOR['alto']}'>Resultados de ejemplo (red ficticia).</p>")
        rows = []
        for r in web_results:
            t = r.target
            if not r.reachable:
                rows.append([_e(t.url), "—", "—", "—", "No respondió"])
                continue
            tls = r.tls
            cipher = (tls.version if tls and tls.version else ("Sin cifrar" if not t.tls else "—"))
            cert = "—"
            if tls and tls.days_left is not None:
                cert = ("Caducado" if tls.days_left < 0 else f"{tls.days_left} días") + \
                    (" · autofirmado" if tls.self_signed else "")
            heads = f"{len(r.headers_present)} de {len(r.headers_present) + len(r.headers_missing)}"
            found = f"{len(r.findings)} · {_sev(r.worst)}" if r.findings else "Ninguno"
            rows.append([_e(t.url), _e(cipher), _e(cert), _e(heads), found])
        p.append(_table(["Servicio", "Cifrado", "Certificado", "Cabeceras", "Hallazgos"], rows,
                        [34, 14, 22, 12, 18]))

    # -------------------------------------------------------- metodología
    p.append("<h2>7. Metodología y alcance</h2>")
    tools = ["nmap (descubrimiento de equipos, puertos y servicios)",
             "Reglas de NMAP Studio (hallazgos por capa OSI)"]
    if cs.before_label:
        tools.append("Comparación de escaneos (vigilancia de cambios)")
    if web_results:
        tools.append("Auditoría web y TLS (una visita a la página principal de cada servicio)")
    p.append("<ul>" + "".join(f"<li>{_e(t)}</li>" for t in tools) + "</ul>")
    if meta.command:
        p.append(f"<p><b>Comando de nmap:</b> <span style='font-family:monospace'>{_e(meta.command)}</span></p>")
    p.append(f"<p style='color:{MUTED}'>Limitaciones: los hallazgos se deducen de lo que nmap y la auditoría "
             "web pueden observar desde la red; no sustituyen una auditoría profesional. Un equipo sin hallazgos "
             "no garantiza que sea seguro.</p>")
    p.append(f"<p style='color:{MUTED}'>Aviso: este análisis solo debe hacerse en redes propias o con permiso "
             "explícito de su dueño.</p>")
    p.append(f"<p style='color:{MUTED}; font-size:8pt'>Generado con NMAP Studio {_e(meta.app_version)} · "
             f"{_e(when)}</p>")
    p.append("</body></html>")
    return "".join(p)
