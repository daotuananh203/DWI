"""Create a PyInstaller Windows version resource from DWI's single version."""

from __future__ import annotations

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from dwi.version import __version__


def _version_parts() -> tuple[int, int, int, int]:
    numbers = [int(value) for value in re.findall(r"\d+", __version__)]
    numbers.extend([0, 0, 0, 0])
    revision = 1 if "rc" in __version__ else 0
    return tuple(numbers[:3]) + (revision,)


def main(path: str) -> int:
    version = _version_parts()
    dotted = ".".join(str(value) for value in version)
    text = f'''# UTF-8
VSVersionInfo(
  ffi=FixedFileInfo(filevers={version}, prodvers={version}, mask=0x3f,
                   flags=0x0, OS=0x40004, fileType=0x1, subtype=0x0,
                   date=(0, 0)),
  kids=[
    StringFileInfo([
      StringTable('040904B0', [
        StringStruct('CompanyName', 'DWI contributors'),
        StringStruct('FileDescription', 'DWI Desktop'),
        StringStruct('FileVersion', '{dotted}'),
        StringStruct('InternalName', 'DWI Desktop'),
        StringStruct('OriginalFilename', 'DWI-{__version__}-Desktop.exe'),
        StringStruct('ProductName', 'Developer Workspace Intelligence'),
        StringStruct('ProductVersion', '{__version__}'),
      ])
    ]),
    VarFileInfo([VarStruct('Translation', [1033, 1200])])
  ]
)
'''
    Path(path).write_text(text, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1]))
