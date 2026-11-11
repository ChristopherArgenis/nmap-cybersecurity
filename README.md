# nmap-cybersecurity

Aplicación de escritorio para correr comandos de **nmap** desde una interfaz gráfica.
Hecha con Python 3.10+ y PySide6 (Qt). Funciona en Windows, Linux y macOS.

Hay **dos versiones** con las mismas funciones y la misma lógica (`nmap_gui/core`):

| Versión | Paquete | Estilo | Ejecutar |
|---|---|---|---|
| 1 · Clásica | `nmap_gui` | Ventana de escritorio tradicional (menús, pestañas) | `python -m nmap_gui` |
| 2 · Moderna (NMAP Studio) | `nmap_gui_v2` | Barra lateral, tarjetas, modo oscuro/claro | `python -m nmap_gui_v2` |

## Descargar el .exe (Windows)

Ve a **[Releases](https://github.com/ChristopherArgenis/nmap-cybersecurity/releases)**,
descarga `NMAP-GUI-v1.exe` o `NMAP-GUI-v2.exe` y ábrelo con doble clic (no necesita Python).
Solo necesitas tener [nmap para Windows](https://nmap.org/download.html) instalado.
Los .exe se compilan solos con GitHub Actions (`.github/workflows/build-windows.yml`).

> ⚠️ **Uso responsable.** Escanea solo redes y equipos propios o donde tengas
> permiso explícito. Escanear redes ajenas (por ejemplo, la red de una escuela
> o empresa) sin autorización puede ser ilegal.

## Funciones

- **Escaneo**: escribe uno o varios objetivos (IP, rango CIDR, dominio), elige un
  perfil y pulsa *Escanear*. La salida de nmap aparece en vivo, con barra de
  progreso y botón *Cancelar*.
- **Constructor de comandos**: casillas y campos para tipo de escaneo, velocidad
  (T0–T5), puertos, detección de versiones/SO, scripts NSE y más. El comando
  resultante se ve (y se copia) en todo momento.
- **Resultados en tabla**: hosts y puertos en un árbol con colores por estado,
  filtro de texto, opción *Solo abiertos* y panel de detalle (SO, MAC, scripts).
- **Historial**: cada escaneo se guarda en SQLite. Puedes abrirlo, repetirlo o borrarlo.
- **Exportar**: TXT, XML de nmap, CSV e informe HTML (Archivo → Exportar).
- **Topología** (versión 2): mapa de la red deducido del escaneo, con zonas
  (infraestructura, equipos, IoT, fuera de la red local), colores por riesgo,
  zoom, detalle de cada equipo y exportación a PNG.
- **Modelo OSI** (versión 2): protocolos y hallazgos de tu red ordenados en las
  7 capas, con explicaciones (modo aprendizaje) y un botón que prepara el escaneo
  recomendado para investigar cada capa.

> Para un mapa y un análisis más completos, usa el perfil *Escaneo intenso* (`-A`):
> añade detección de sistema operativo, versiones y `--traceroute`. Los hallazgos
> son orientativos y se deducen de lo que nmap reporta.
  También puedes abrir un XML generado por nmap en otro lugar (Archivo → Abrir).

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
