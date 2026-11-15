"""Convierte el HTML del reporte en un PDF con las herramientas de Qt (sin dependencias extra)."""

from __future__ import annotations

import sys

from PySide6.QtCore import QMarginsF, QUrl
from PySide6.QtGui import QFont, QImage, QPageLayout, QPageSize, QPdfWriter, QTextDocument


def write_pdf(html_text: str, path: str, images: dict[str, QImage] | None = None,
              title: str = "Informe de seguridad de la red", author: str = "") -> str:
    writer = QPdfWriter(path)
    writer.setPageSize(QPageSize(QPageSize.PageSizeId.A4))
    writer.setPageMargins(QMarginsF(16, 16, 16, 16), QPageLayout.Unit.Millimeter)
    writer.setResolution(144)
    writer.setTitle(title)
    writer.setCreator("NMAP Studio")
    if author:
        writer.setAuthor(author)

    doc = QTextDocument()
    font = QFont("Segoe UI" if sys.platform == "win32" else "DejaVu Sans")
    font.setPointSizeF(9.5)
    doc.setDefaultFont(font)
    doc.setDefaultStyleSheet("h1 { margin-top: 0; } h2 { margin-top: 18px; } h3 { margin-top: 12px; }")
    for name, img in (images or {}).items():
        doc.addResource(QTextDocument.ResourceType.ImageResource, QUrl(name), img)
    doc.setHtml(html_text)
    doc.print_(writer)  # pagina el documento y numera las páginas
    return path
