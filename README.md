# nmap-cybersecurity

Aplicación de escritorio para correr comandos de **nmap** desde una interfaz gráfica.
Hecha con Python 3.10+ y PySide6 (Qt). Funciona en Windows, Linux y macOS.

Hay **dos versiones** con las mismas funciones y la misma lógica (`nmap_gui/core`):

| Versión | Paquete | Estilo | Ejecutar |
|---|---|---|---|
| 1 · Clásica | `nmap_gui` | Ventana de escritorio tradicional (menús, pestañas) | `python -m nmap_gui` |
| 2 · Moderna (NMAP Studio) | `nmap_gui_v2` | Barra lateral, tarjetas, modo oscuro/claro | `python -m nmap_gui_v2` |

## Descargar para Windows

1. Ve a **[Releases](https://github.com/ChristopherArgenis/nmap-cybersecurity/releases)** y
   descarga `NMAP-Studio-v…-windows.zip` (versión 2) o `NMAP-GUI-v…-windows.zip` (versión 1).
2. Clic derecho en el .zip → **Propiedades** → marca **Desbloquear** → Aceptar.
3. Descomprímelo y abre el `.exe` que hay dentro de la carpeta. No necesita Python.
4. Si Windows muestra «Windows protegió su PC»: **Más información → Ejecutar de todas formas**.
   Aparece porque la app no tiene firma digital de pago; el código es abierto aquí mismo.

Para verla sin escanear nada: **Ajustes → Cargar red de ejemplo** (una red de casa ficticia).
Para escanear de verdad instala [nmap para Windows](https://nmap.org/download.html).
Los paquetes se compilan solos con GitHub Actions (`.github/workflows/build-windows.yml`),
que antes de publicar abre la app en Windows para comprobar que arranca.

## Requisitos

1. **nmap** instalado: <https://nmap.org/download.html>
   (Linux: `sudo apt install nmap` · macOS: `brew install nmap` · Windows: instalador oficial).
   Si la app no lo encuentra, indica la ruta en *Herramientas → Ruta de nmap*.
2. **Python 3.10 o superior**.

## Instalación y uso

```bash
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python -m nmap_gui
```

Algunos escaneos (SYN `-sS`, UDP `-sU`, detección de SO `-O`, agresivo `-A`)
requieren permisos de administrador. En Linux/macOS: `sudo .venv/bin/python -m nmap_gui`;
en Windows, abre la terminal "como administrador".

## Pruebas

Las pruebas usan un **nmap simulado** (`tests/fake_nmap.py`) que no envía nada a la red.

```bash
pip install -r requirements-dev.txt
pytest
```

## Estructura

```
nmap_gui/
  core/                 lógica sin interfaz (fácil de probar)
    command_builder.py  opciones → argumentos de nmap, con validación
    scanner.py          ejecuta nmap con QProcess (sin shell) y lee el XML
    parser.py           XML de nmap → objetos Host / Port
    history.py          historial en SQLite
    exporter.py         TXT / XML / CSV / HTML
  ui/                   ventanas y paneles PySide6 (versión 1)
nmap_gui_v2/            versión 2: tema, iconos, componentes y páginas
  core/                 hallazgos, topología y modelo OSI (sin interfaz)
packaging/              entradas para PyInstaller e icono
tests/                  pruebas con pytest
```

## Seguridad

- nmap se lanza con una lista de argumentos, **nunca a través de un shell**, así que
  no hay inyección de comandos.
- Los objetivos, puertos y scripts se validan; no se aceptan objetivos que empiecen
  con `-` ni opciones de salida (`-oN`, `-oX`…) en los argumentos extra.
- Al abrir la app por primera vez se muestra un aviso de uso responsable.

## Próximos pasos

- Empaquetar también para Linux (AppImage) y macOS (`.app`).
- Comparar dos escaneos del historial (puertos nuevos o cerrados).
- Topología de red visual y perfiles guardados por el usuario.

## Cómo se hizo

Este proyecto se desarrolló con ayuda de IA ([Claude Code](https://claude.com/claude-code))
como asistente de programación. La idea, las decisiones de diseño, las pruebas y el
mantenimiento son de su autor.

## Licencia

Distribuido bajo la [licencia MIT](LICENSE): puedes usar, copiar, modificar y
compartir este proyecto libremente, manteniendo el aviso de copyright.

nmap es un programa aparte con su propia licencia (<https://nmap.org/npsl/>);
esta aplicación no lo incluye, solo lo ejecuta si está instalado.
