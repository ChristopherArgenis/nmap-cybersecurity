"""Genera el archivo de versión de Windows que PyInstaller incrusta en el .exe.

Uso: python packaging/make_version_file.py <salida> <nombre> <descripción> <versión X.Y.Z>
Así el .exe muestra autor, nombre y versión en Propiedades → Detalles.
"""
import sys
from pathlib import Path

out, name, description, version = sys.argv[1:5]
parts = [int(x) for x in version.split(".")] + [0] * (4 - len(version.split(".")))
nums = tuple(parts[:4])
text = f"""# UTF-8
VSVersionInfo(
  ffi=FixedFileInfo(filevers={nums}, prodvers={nums}, mask=0x3f, flags=0x0, OS=0x40004,
                    fileType=0x1, subtype=0x0, date=(0, 0)),
  kids=[
    StringFileInfo([StringTable('080A04B0', [
      StringStruct('CompanyName', 'Christopher Argenis Preciado Silva'),
      StringStruct('FileDescription', {description!r}),
      StringStruct('FileVersion', {version!r}),
      StringStruct('InternalName', {name!r}),
      StringStruct('LegalCopyright', 'Licencia MIT'),
      StringStruct('OriginalFilename', {name + '.exe'!r}),
      StringStruct('ProductName', {name!r}),
      StringStruct('ProductVersion', {version!r})])]),
    VarFileInfo([VarStruct('Translation', [0x080A, 1200])])
  ]
)
"""
Path(out).parent.mkdir(parents=True, exist_ok=True)
with open(out, "w", encoding="utf-8") as fh:
    fh.write(text)
print("versión escrita en", out)
