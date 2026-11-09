"""Paletas de color y hoja de estilos (QSS) de la versión moderna."""

from __future__ import annotations

THEMES: dict[str, dict[str, str]] = {
    "oscuro": {
        "bg": "#0b1120",
        "sidebar": "#0a0f1c",
        "card": "#131b2e",
        "card2": "#18223a",
        "border": "#233049",
        "text": "#e6eaf2",
        "muted": "#8b97ad",
        "accent": "#10b981",
        "accent_hover": "#34d399",
        "accent_text": "#03140d",
        "accent_soft": "rgba(16,185,129,0.14)",
        "danger": "#f43f5e",
        "warn": "#f59e0b",
        "info": "#38bdf8",
        "console": "#070b14",
        "console_text": "#a7f3d0",
        "selection": "#1f3a5f",
    },
    "claro": {
        "bg": "#f3f5fa",
        "sidebar": "#ffffff",
        "card": "#ffffff",
        "card2": "#f7f9fc",
        "border": "#e1e6ef",
        "text": "#0f172a",
        "muted": "#64748b",
        "accent": "#059669",
        "accent_hover": "#10b981",
        "accent_text": "#ffffff",
        "accent_soft": "rgba(5,150,105,0.10)",
        "danger": "#e11d48",
        "warn": "#d97706",
        "info": "#0284c7",
        "console": "#0f172a",
        "console_text": "#a7f3d0",
        "selection": "#dbeafe",
    },
}

STATE_COLORS = {"open": "accent", "closed": "danger", "filtered": "warn", "up": "accent", "down": "danger"}

_QSS = """
* { font-size: 13px; color: {text}; }
QMainWindow, #Root { background: {bg}; }
QToolTip { background: {card2}; color: {text}; border: 1px solid {border}; padding: 4px 8px; }

/* ---------- Barra lateral ---------- */
#Sidebar { background: {sidebar}; border-right: 1px solid {border}; }
#Brand { font-size: 17px; font-weight: 700; }
#BrandSub { color: {muted}; font-size: 11px; }
#NavButton {
    text-align: left; padding: 10px 14px; border: none; border-radius: 10px;
    background: transparent; color: {muted}; font-weight: 600;
}
#NavButton:hover { background: {card2}; color: {text}; }
#NavButton:checked { background: {accent_soft}; color: {accent}; }
#SidebarFoot { color: {muted}; font-size: 11px; }

/* ---------- Tarjetas y textos ---------- */
#Card { background: {card}; border: 1px solid {border}; border-radius: 14px; }
#PageTitle { font-size: 22px; font-weight: 700; }
#PageSubtitle { color: {muted}; }
#CardTitle { font-size: 14px; font-weight: 700; }
#Muted { color: {muted}; }
#StatValue { font-size: 26px; font-weight: 700; }
#StatLabel { color: {muted}; font-size: 12px; }

/* ---------- Entradas ---------- */
QLineEdit, QComboBox {
    background: {card2}; border: 1px solid {border}; border-radius: 9px;
    padding: 7px 10px; selection-background-color: {accent};
}
QLineEdit:focus, QComboBox:focus { border: 1px solid {accent}; }
QLineEdit:disabled, QComboBox:disabled { color: {muted}; }
#HeroInput { font-size: 16px; padding: 12px 16px; border-radius: 12px; }
QComboBox::drop-down { border: none; width: 24px; }
QComboBox QAbstractItemView {
    background: {card}; border: 1px solid {border}; selection-background-color: {accent_soft};
    selection-color: {text}; outline: 0;
}

/* ---------- Botones ---------- */
QPushButton {
    background: {card2}; border: 1px solid {border}; border-radius: 9px; padding: 8px 14px; font-weight: 600;
}
QPushButton:hover { border-color: {accent}; }
QPushButton:disabled { color: {muted}; }
#PrimaryButton { background: {accent}; color: {accent_text}; border: none; padding: 12px 22px; font-size: 14px; }
#PrimaryButton:hover { background: {accent_hover}; }
#PrimaryButton:disabled { background: {border}; color: {muted}; }
#AccentButton { background: {accent}; color: {accent_text}; border: none; }
#AccentButton:hover { background: {accent_hover}; }
#AccentButton:disabled { background: {border}; color: {muted}; }
#DangerButton { background: transparent; color: {danger}; border: 1px solid {danger}; padding: 12px 18px; }
#DangerButton:hover { background: {danger}; color: white; }
#Chip {
    background: {card2}; border: 1px solid {border}; border-radius: 12px; min-height: 18px; padding: 6px 14px;
    color: {muted}; font-weight: 600;
}
#Chip:hover { color: {text}; }
#Chip:checked { background: {accent_soft}; border-color: {accent}; color: {accent}; }
#LinkButton { background: transparent; border: none; color: {accent}; padding: 4px 6px; }
#LinkButton:hover { color: {accent_hover}; }

/* ---------- Código y consola ---------- */
#CodeBox {
    background: {console}; color: {console_text}; border: 1px solid {border}; border-radius: 9px;
    padding: 9px 12px; font-family: "Cascadia Code", "JetBrains Mono", "Consolas", monospace;
}
#Console {
    background: {console}; color: {console_text}; border: none; border-radius: 10px; padding: 10px;
    font-family: "Cascadia Code", "JetBrains Mono", "Consolas", monospace; font-size: 12px;
    selection-background-color: {selection};
}
QProgressBar { background: {card2}; border: none; border-radius: 3px; max-height: 6px; }
QProgressBar::chunk { background: {accent}; border-radius: 3px; }

/* ---------- Listas y tablas ---------- */
QListWidget, QTableWidget, QTableView, QPlainTextEdit#Detail {
    background: {card}; border: none; outline: 0; alternate-background-color: {card2};
}
QListWidget::item { padding: 10px; border-radius: 10px; margin: 2px 0; }
QListWidget::item:hover { background: {card2}; }
QListWidget::item:selected { background: {accent_soft}; color: {text}; }
QTableWidget, QTableView { gridline-color: transparent; selection-background-color: {selection}; selection-color: {text}; }
QTableWidget::item { padding: 6px; border-bottom: 1px solid {border}; }
QHeaderView::section {
    background: {card}; color: {muted}; border: none; border-bottom: 1px solid {border};
    padding: 8px 6px; font-weight: 700; font-size: 11px; text-transform: uppercase;
}
QTableCornerButton::section { background: {card}; border: none; }

/* ---------- Scroll ---------- */
QScrollArea { background: transparent; border: none; }
QScrollArea > QWidget > QWidget { background: transparent; }
QScrollBar:vertical { background: transparent; width: 10px; margin: 2px; }
QScrollBar::handle:vertical { background: {border}; border-radius: 4px; min-height: 30px; }
QScrollBar:horizontal { background: transparent; height: 10px; margin: 2px; }
QScrollBar::handle:horizontal { background: {border}; border-radius: 4px; min-width: 30px; }
QScrollBar::add-line, QScrollBar::sub-line { width: 0; height: 0; }
QScrollBar::add-page, QScrollBar::sub-page { background: none; }

QSplitter::handle { background: transparent; }
QMessageBox { background: {card}; }
QMenu { background: {card}; border: 1px solid {border}; padding: 4px; }
QMenu::item { padding: 6px 18px; border-radius: 6px; }
QMenu::item:selected { background: {accent_soft}; }
"""


def stylesheet(theme: str) -> str:
    colors = THEMES[theme]
    qss = _QSS
    for key, value in colors.items():
        qss = qss.replace("{" + key + "}", value)
    return qss


def color(theme: str, key: str) -> str:
    return THEMES[theme][key]
