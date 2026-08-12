# Dependency and license audit

The release candidate has no runtime Python dependencies beyond the Python
standard library and Tkinter supplied by the supported Python installation.
The project license is MIT; the file is [LICENSE](../LICENSE).

| Component | Version used/constraint | Purpose | License / distribution | Status |
|---|---|---|---|---|
| Python standard library | Python 3.12.8 evaluation; `>=3.11` | Runtime, Tkinter integration, JSON-RPC | Python Software Foundation; supplied by Python | Verified as host prerequisite |
| setuptools | `>=68` build-system constraint; 84.0.0 RC build env | PEP 517 build backend | MIT (`License-Expression`); build-only, not bundled | Verified from package metadata |
| build | 1.5.0 RC build env | Wheel/sdist frontend | MIT (`License-Expression`); build-only, not bundled | Verified from package metadata |
| PyInstaller | 6.22.0 RC build env | Optional Windows Desktop bundling | GPLv2-or-later with special exception for distributing built programs; build-only, not bundled in Python package | Verify artifact notices before distribution |
| Inno Setup | 7.0.2 validation tool | Optional Windows installer | Inno Setup License; DWI does not distribute the compiler | License and output-distribution conditions verified |

No MCP SDK, cloud SDK, telemetry library, analytics package, HTTP server or
network client is used. Build tools stay in an isolated environment. The
PyInstaller exception and any Inno Setup notices must remain available with
their corresponding release artifacts; they are not runtime DWI dependencies.

## Inno Setup distribution conclusion

The authoritative [Inno Setup License](https://jrsoftware.org/files/is/license.txt)
grants permission to use the software for any purpose, including commercial
applications, and to alter and redistribute it subject to its conditions. The
relevant conditions include retaining copyright notices and the stated website
addresses in binary redistributions, not misrepresenting origin, and plainly
marking modified versions. The official [Inno Setup FAQ](https://jrsoftware.org/isfaq.php)
also states that redistributing the compiler is permissible when the license
terms are followed.

DWI does not distribute `ISCC.exe`, the Inno Setup compiler, or its tool
installation. DWI distributes only the compiled DWI installer output. The
installer must retain the Inno Setup notices present in its embedded setup
components; DWI does not relicense those components under MIT. The DWI
installer script is not a modified Inno Setup compiler. On that documented
distribution model, the Inno Setup gate is compatible and **PASS**.

License compatibility is limited to the stated distribution model. If a
future build bundles third-party components, regenerate this audit from the
actual artifact metadata and include all required notices.
