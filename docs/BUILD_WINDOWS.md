# Windows Packaging Foundation

`pyproject.toml` is the single package metadata source. Runtime dependencies
remain empty; Desktop EN/VI JSON resources are declared as package data, and
the `dwi` and `dwi-mcp` console entry points are defined for installation.
Version `1.0.0.dev1` is sourced from `dwi.version.__version__` and is shared by
package metadata, CLI, Desktop, and MCP.

The reproducible build foundation is `scripts/build_windows.ps1`. In an
isolated build environment with the optional `build` package installed, run:

```powershell
./scripts/build_windows.ps1
```

The script compiles Python and creates wheel/sdist artifacts in `dist/`; it
does not commit generated binaries. Final Windows installer technology and
branding remain v1.0 release-polish work.

`scripts/clean_env_smoke.py` provides a dependency-free import, CLI, Desktop,
and MCP entry-point smoke after installation or from the source checkout.
