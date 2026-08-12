# Installation

This page describes only installation paths supported by the release candidate
validation record. DWI targets Windows and Python 3.11 or newer.

## Python wheel

Install the wheel in a fresh virtual environment:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install .\dwi-1.0.0rc1-py3-none-any.whl
.\.venv\Scripts\dwi.exe --version
```

The wheel contains the `dwi` and `dwi-mcp` entry points, Desktop EN/VI
resources, and no runtime dependency outside Python. Batch 2 validation runs
these commands from outside the source checkout to prove imports resolve from
the installed distribution.

## Source distribution

The sdist requires a Python packaging build environment. In a fresh
environment, install the sdist and let the build frontend create the wheel:

```powershell
python -m venv .venv-sdist
.\.venv-sdist\Scripts\python.exe -m pip install .\dwi-1.0.0rc1.tar.gz
.\.venv-sdist\Scripts\dwi.exe --version
```

## Portable Desktop

The PyInstaller build produces a windowed executable and a ZIP archive. The
portable archive does not install a CLI or MCP command globally; use the wheel
for those entry points. The archive is not an installer and has no elevated
privilege requirement.

## Windows installer

The repository includes an Inno Setup configuration and wrapper script. An
installer is available for the RC and was validated in a disposable Windows
temp-root environment. It installs the Desktop artifact only; install the
wheel separately for the `dwi` and `dwi-mcp` entry points. The EXE and
installer are intentionally unsigned, so Windows SmartScreen may warn. Verify
SHA-256 using [RELEASE_ARTIFACTS.md](RELEASE_ARTIFACTS.md). No trusted
certificate is currently available and no signing claim is made.

## Development source

```powershell
Set-Location DWI  # a source checkout obtained through the project's configured repository channel
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install pytest==9.1.1  # test-only
.\.venv\Scripts\python.exe -m pytest -q
```

Build tools such as `build` and `PyInstaller` belong in an isolated build
environment and are not DWI runtime dependencies. See
[BUILD_WINDOWS.md](BUILD_WINDOWS.md).
