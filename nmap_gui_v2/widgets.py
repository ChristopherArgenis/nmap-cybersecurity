"""Componentes visuales reutilizables de la versión moderna."""

from __future__ import annotations

from PySide6.QtCore import Property, QEasingCurve, QPropertyAnimation, QRectF, QSize, Qt
from PySide6.QtGui import QColor, QPainter
from PySide6.QtWidgets import (
    QAbstractButton,
    QFrame,
    QGraphicsDropShadowEffect,
    QLabel,
    QStyle,
    QStyledItemDelegate,
    QStyleOptionViewItem,
    QVBoxLayout,
    QWidget,
)


class Card(QFrame):
    """Contenedor con fondo, borde redondeado y sombra suave."""

    def __init__(self, title: str = "", parent: QWidget | None = None, shadow: bool = True):
        super().__init__(parent)
        self.setObjectName("Card")
        self.body = QVBoxLayout(self)
        self.body.setContentsMargins(18, 16, 18, 16)
        self.body.setSpacing(12)
        if title:
            lbl = QLabel(title)
            lbl.setObjectName("CardTitle")
            self.body.addWidget(lbl)
        if shadow:
            fx = QGraphicsDropShadowEffect(self)
            fx.setBlurRadius(24)
            fx.setOffset(0, 4)
            fx.setColor(QColor(0, 0, 0, 40))
            self.setGraphicsEffect(fx)


class StatCard(Card):
    def __init__(self, label: str, accent: str = "", parent: QWidget | None = None):
        super().__init__(parent=parent)
        self.value = QLabel("—")
        self.value.setObjectName("StatValue")
        self.label = QLabel(label)
        self.label.setObjectName("StatLabel")
        self.body.setSpacing(2)
        self.body.addWidget(self.value)
        self.body.addWidget(self.label)
        self.set_accent(accent)

    def set_accent(self, color: str) -> None:
        if color:
            self.value.setStyleSheet(f"color: {color};")

    def set_value(self, text: str) -> None:
        self.value.setText(text)


class ToggleSwitch(QAbstractButton):
    """Interruptor animado tipo móvil. Se usa como un QCheckBox."""

    def __init__(self, text: str = "", parent: QWidget | None = None):
        super().__init__(parent)
        self.setCheckable(True)
        self.setText(text)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self._pos = 0.0
        self._anim = QPropertyAnimation(self, b"knob", self)
        self._anim.setDuration(140)
        self._anim.setEasingCurve(QEasingCurve.Type.OutCubic)
        self.toggled.connect(self._animate)
        self.on_color = QColor("#10b981")
        self.off_color = QColor("#334155")
        self.text_color = QColor("#e6eaf2")
        self.muted_color = QColor("#8b97ad")

    def set_colors(self, on: str, off: str, text: str, muted: str) -> None:
        self.on_color, self.off_color = QColor(on), QColor(off)
        self.text_color, self.muted_color = QColor(text), QColor(muted)
        self.update()

    def _get_knob(self) -> float:
        return self._pos

    def _set_knob(self, value: float) -> None:
        self._pos = value
        self.update()

    knob = Property(float, _get_knob, _set_knob)

    def _animate(self, checked: bool) -> None:
        self._anim.stop()
        self._anim.setEndValue(1.0 if checked else 0.0)
        self._anim.start()

    def setChecked(self, checked: bool) -> None:  # noqa: N802 (API de Qt)
        super().setChecked(checked)
        self._anim.stop()
        self._pos = 1.0 if checked else 0.0
        self.update()

    def sizeHint(self) -> QSize:  # noqa: N802
        w = 44 + 10 + self.fontMetrics().horizontalAdvance(self.text())
        return QSize(w, 26)

    def paintEvent(self, _event) -> None:  # noqa: N802
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        enabled = self.isEnabled()
        track = QRectF(0, 4, 38, 20)
        c = QColor(self.off_color)
        if self._pos > 0:
            c = _mix(self.off_color, self.on_color, self._pos)
        if not enabled:
            c.setAlpha(90)
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(c)
        p.drawRoundedRect(track, 10, 10)
        knob_x = 3 + self._pos * 18
        p.setBrush(QColor(255, 255, 255, 255 if enabled else 140))
        p.drawEllipse(QRectF(knob_x, 7, 14, 14))
        p.setPen(self.text_color if enabled else self.muted_color)
        p.drawText(QRectF(48, 0, self.width() - 48, self.height()), Qt.AlignmentFlag.AlignVCenter, self.text())

    def hitButton(self, pos) -> bool:  # noqa: N802
        return self.rect().contains(pos)


def _mix(a: QColor, b: QColor, t: float) -> QColor:
    return QColor(
        int(a.red() + (b.red() - a.red()) * t),
        int(a.green() + (b.green() - a.green()) * t),
        int(a.blue() + (b.blue() - a.blue()) * t),
    )


class PillDelegate(QStyledItemDelegate):
    """Pinta el estado (open/closed/filtered) como una etiqueta redondeada de color."""

    def __init__(self, colors: dict[str, str], parent=None):
        super().__init__(parent)
        self.colors = colors
        self.line = "#233049"

    def paint(self, painter: QPainter, option: QStyleOptionViewItem, index) -> None:
        text = str(index.data() or "")
        if not text:
            return super().paint(painter, option, index)
        if option.state & QStyle.StateFlag.State_Selected:
            painter.fillRect(option.rect, option.palette.highlight())
        painter.save()
        painter.setPen(QColor(self.line))
        painter.drawLine(option.rect.bottomLeft(), option.rect.bottomRight())
        painter.restore()
        key = text.split("|")[0]
        base = QColor(self.colors.get(key, "#8b97ad"))
        painter.save()
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        fm = option.fontMetrics
        w = fm.horizontalAdvance(text) + 18
        h = fm.height() + 6
        r = QRectF(option.rect.x() + 6, option.rect.center().y() - h / 2 + 1, w, h)
        bg = QColor(base)
        bg.setAlpha(40)
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(bg)
        painter.drawRoundedRect(r, h / 2, h / 2)
        painter.setPen(base)
        f = painter.font()
        f.setBold(True)
        painter.setFont(f)
        painter.drawText(r, Qt.AlignmentFlag.AlignCenter, text)
        painter.restore()
