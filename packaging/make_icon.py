"""Genera packaging/icon.ico y icon.png a partir de un SVG (requiere PySide6)."""
import sys
from pathlib import Path

from PySide6.QtCore import QByteArray, Qt
from PySide6.QtGui import QGuiApplication, QImage, QPainter
from PySide6.QtSvg import QSvgRenderer

SVG = """<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 256 256'>
<rect width='256' height='256' rx='56' fill='#0f172a'/>
<circle cx='128' cy='128' r='84' fill='none' stroke='#10b981' stroke-width='10' opacity='.35'/>
<circle cx='128' cy='128' r='52' fill='none' stroke='#10b981' stroke-width='10' opacity='.6'/>
<path d='M128 128 L190 70' stroke='#34d399' stroke-width='14' stroke-linecap='round'/>
<circle cx='128' cy='128' r='14' fill='#34d399'/>
<circle cx='176' cy='150' r='10' fill='#f59e0b'/>
<circle cx='92' cy='92' r='8' fill='#38bdf8'/>
</svg>"""

out = Path(__file__).parent
app = QGuiApplication(sys.argv)
renderer = QSvgRenderer(QByteArray(SVG.encode()))
img = QImage(256, 256, QImage.Format.Format_ARGB32)
img.fill(Qt.GlobalColor.transparent)
p = QPainter(img)
renderer.render(p)
p.end()
img.save(str(out / "icon.png"))
ok = img.save(str(out / "icon.ico"))
print("icon.ico", "ok" if ok else "FALLÓ")
