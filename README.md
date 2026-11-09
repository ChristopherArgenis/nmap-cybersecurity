# nmap-cybersecurity

Aplicación de escritorio para correr comandos de **nmap** desde una interfaz gráfica.
Hecha con Python 3.10+ y PySide6 (Qt). Funciona en Windows, Linux y macOS.

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
  ui/                   ventanas y paneles PySide6
tests/                  pruebas con pytest
```

## Seguridad

- nmap se lanza con una lista de argumentos, **nunca a través de un shell**, así que
  no hay inyección de comandos.
- Los objetivos, puertos y scripts se validan; no se aceptan objetivos que empiecen
  con `-` ni opciones de salida (`-oN`, `-oX`…) en los argumentos extra.
- Al abrir la app por primera vez se muestra un aviso de uso responsable.

## Próximos pasos

- Empaquetar como ejecutable con PyInstaller (`.exe` / AppImage / `.app`).
- Comparar dos escaneos del historial (puertos nuevos o cerrados).
- Topología de red visual y perfiles guardados por el usuario.
