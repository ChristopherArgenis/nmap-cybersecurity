"""Iconos vectoriales simples (SVG de trazo) coloreados en tiempo de ejecución."""

from __future__ import annotations

from PySide6.QtCore import QByteArray, QSize, Qt
from PySide6.QtGui import QIcon, QPainter, QPixmap
from PySide6.QtSvg import QSvgRenderer

_PATHS = {
    "radar": "<circle cx='12' cy='12' r='9'/><circle cx='12' cy='12' r='5'/><path d='M12 12l6-6'/>"
             "<circle cx='12' cy='12' r='1' fill='C'/>",
    "results": "<rect x='3' y='4' width='18' height='16' rx='2'/><path d='M3 10h18M9 10v10'/>",
    "history": "<path d='M3 12a9 9 0 1 0 3-6.7L3 8'/><path d='M3 3v5h5'/><path d='M12 7v5l3 2'/>",
    "settings": "<circle cx='12' cy='12' r='3'/><path d='M12 2v3M12 19v3M4.9 4.9l2.1 2.1M17 17l2.1 2.1"
                "M2 12h3M19 12h3M4.9 19.1L7 17M17 7l2.1-2.1'/>",
    "play": "<path d='M7 4l13 8-13 8z' fill='C'/>",
    "stop": "<rect x='6' y='6' width='12' height='12' rx='2' fill='C'/>",
    "copy": "<rect x='9' y='9' width='12' height='12' rx='2'/><path d='M5 15V5a2 2 0 0 1 2-2h8'/>",
    "export": "<path d='M12 3v12M7 8l5-5 5 5'/><path d='M4 15v4a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-4'/>",
    "open": "<path d='M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z'/>",
    "trash": "<path d='M4 7h16M9 7V4h6v3M6 7l1 13h10l1-13'/>",
    "repeat": "<path d='M17 2l4 4-4 4'/><path d='M3 12V10a4 4 0 0 1 4-4h14'/><path d='M7 22l-4-4 4-4'/>"
              "<path d='M21 12v2a4 4 0 0 1-4 4H3'/>",
    "chevron": "<path d='M9 6l6 6-6 6'/>",
    "shield": "<path d='M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z'/>",
    "topology": "<circle cx='12' cy='5' r='2.5'/><circle cx='5' cy='19' r='2.5'/><circle cx='19' cy='19' r='2.5'/>"
                "<path d='M12 7.5v4M12 11.5L6.5 17M12 11.5l5.5 5.5'/>",
    "layers": "<path d='M12 3l9 5-9 5-9-5z'/><path d='M3 13l9 5 9-5'/><path d='M3 17.5l9 5 9-5' opacity='.5'/>",
    "fit": "<path d='M4 9V4h5M20 9V4h-5M4 15v5h5M20 15v5h-5'/>",
    "image": "<rect x='3' y='4' width='18' height='16' rx='2'/><circle cx='9' cy='10' r='2'/><path d='M21 17l-5-5-8 8'/>",
    "host": "<rect x='3' y='4' width='18' height='12' rx='2'/><path d='M8 20h8M12 16v4'/>",
}


def icon(name: str, color: str, size: int = 18) -> QIcon:
    body = _PATHS[name].replace("'C'", f"'{color}'")
    svg = (
        f"<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='{color}' "
        f"stroke-width='2' stroke-linecap='round' stroke-linejoin='round'>{body}</svg>"
    )
    renderer = QSvgRenderer(QByteArray(svg.encode()))
    pm = QPixmap(QSize(size * 2, size * 2))
    pm.fill(Qt.GlobalColor.transparent)
    painter = QPainter(pm)
    renderer.render(painter)
    painter.end()
    pm.setDevicePixelRatio(2)
    return QIcon(pm)
