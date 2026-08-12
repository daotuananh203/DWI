# Windows Packaging and Release-Candidate Build

`pyproject.toml` is the single package metadata source. Runtime dependencies
remain empty; Desktop EN/VI JSON resources are declared as package data, and
the `dwi` and `dwi-mcp` console entry points are defined for installation.
Version `1.0.0rc1` is sourced from `dwi.version.__version__` and is shared by
package metadata, CLI, Desktop, and MCP.

Use an isolated build environment for packaging tools. The runtime package
does not depend on them:

```powershell
python -m venv $env:TEMP\dwi-build-env
$env:TEMP\dwi-build-env\Scripts\python.exe -m pip install build pyinstaller
```

Build wheel and sdist with:

```powershell
./scripts/build_windows.ps1 -Python $env:TEMP\dwi-build-env\Scripts\python.exe -OutputDirectory release-artifacts\python
```

The script compiles Python and creates wheel/sdist artifacts. Inspect the
actual metadata and contents before distribution; generated artifacts remain
ignored and outside committed source files.

Build a Desktop executable with PyInstaller:

```powershell
./scripts/build_windows_app.ps1 -Python $env:TEMP\dwi-build-env\Scripts\python.exe -OutputDirectory release-artifacts\windows
```

This produces a windowed, source-independent Desktop executable and a
portable ZIP when the build completes. The build script embeds the single
source version and includes EN/VI resources. It does not perform cleanup on
launch. The RC artifact name is x64 only when the build host reports
`AMD64`/`x86_64`.

The repository contains an Inno Setup script at
`packaging/dwi_installer.iss` and a wrapper at
`scripts/build_windows_installer.ps1`. The RC installer is intentionally
unsigned; Windows SmartScreen may warn. Verify SHA-256 from
`docs/RELEASE_ARTIFACTS.md`. DWI does not distribute the Inno Setup compiler;
the verified Inno Setup License and compiled-output distribution model are
documented in `docs/DEPENDENCY_LICENSES.md`.
The installer name and `AppVersion` remain `1.0.0rc1`; its Windows fixed
numeric version resource uses `1.0.0.1` for the pre-release build.

`scripts/clean_env_smoke.py` provides a dependency-free import, CLI, Desktop,
and MCP entry-point smoke after installation. It must be run from outside the
repository when validating a wheel or sdist.
