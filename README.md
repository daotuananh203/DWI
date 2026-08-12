# Developer Workspace Intelligence (DWI)

DWI is a Windows-first developer-storage intelligence and safe-cleanup system.
It discovers development artifacts, explains the evidence behind each finding,
and provides reversible Quarantine + Journal + Undo workflows through one
deterministic engine.

This repository contains the `1.0.0` stable release.

[Đọc README tiếng Việt](README.vi.md)

## What DWI provides

- Workspace Intelligence for Python, Node.js and approved developer-storage
  artifacts.
- System Intelligence with bounded traversal, partial-result reporting and
  network-filesystem default deny.
- A deterministic evidence → interpretation → Safety Policy pipeline.
- Native Tkinter Desktop with English/Vietnamese resources.
- CLI reporting and human-confirmed cleanup.
- Local stdio MCP tools for untrusted AI-agent callers.
- Reversible Quarantine + Journal + Undo. Permanent deletion is not provided.

The safety engine, not an AI model, decides `RiskLabel`, `ActionEligibility`,
validation and authorization. AI may explain or request an engine decision; it
must never manufacture a safety decision.

## Install the 1.0.0 release

Validated Python package installation uses Python 3.11+ on Windows:

```powershell
python -m pip install dwi-1.0.0-py3-none-any.whl
```

The wheel has no runtime dependencies beyond Python. A source distribution is
also provided for environments that build Python packages locally. See
[installation](docs/INSTALLATION.md) for wheel, sdist, portable Desktop and
development-source instructions. A Windows installer is a separate artifact
and has been installed and smoke-tested in a disposable Windows temp-root
environment. The EXE and installer are intentionally unsigned; Windows may
show a SmartScreen warning. Verify the SHA-256 values in
[docs/RELEASE_ARTIFACTS.md](docs/RELEASE_ARTIFACTS.md), and do not interpret
the artifacts as trusted code-signed binaries.

## Quick start

```powershell
dwi --version
dwi scan PATH --json
dwi scan-system --root PATH --json
dwi cleanup PATH --json
dwi desktop
dwi-mcp
```

For source checkouts, replace `dwi` with `python -m dwi`. CLI details are in
[docs/CLI.md](docs/CLI.md), and Desktop details are in
[docs/DESKTOP.md](docs/DESKTOP.md).

Cleanup requires an exact human review and confirmation. It never accepts an
arbitrary mutation path from an agent. Each item is revalidated immediately
before the reversible quarantine move; partial results and reconciliation
states remain explicit.

## MCP agent boundary

Start the local server with:

```powershell
dwi-mcp
```

The transport is stdin/stdout only. The 13 tools expose read-only scans,
findings, explanations, cleanup review, trusted-human-confirmation status,
fresh-revalidated execution requests, recovery status and recovery-handle Undo.
The MCP caller is untrusted:

- no raw-path mutation tool exists;
- no agent-supplied confirmation phrase creates human consent;
- no caller-supplied risk, validation, authorization or trusted snapshot is
  accepted;
- handles are server-owned, bounded, expiring and invalidated on restart;
- roots, finding selections, messages and pages have hard limits.

Read [docs/MCP.md](docs/MCP.md) for the complete workflow. DWI is offline-first:
there is no telemetry, analytics, cloud API, hidden update check or default
network listener.

## Safety and limitations

DWI is conservative when evidence is missing, failed, partial, conflicting or
ambiguous. Confirmed reachability and protected roots veto cleanup eligibility.
Links/reparse points are not followed, `.git` is context/protection rather than
a cleanup candidate, and the Windows mutation gate rejects protected, network,
reparse, root-escape and alias cases.

Cleanup is deliberately limited to reversible Quarantine + Journal + Undo.
The release candidate does not claim transactional filesystem semantics,
crash-proof atomicity, automatic cleanup, permanent deletion, cloud operation,
or trusted code signing. Windows SmartScreen may warn because the RC EXE and
installer are unsigned. See [docs/SAFETY_INVARIANTS.md](docs/SAFETY_INVARIANTS.md)
and [docs/RELEASE_READINESS.md](docs/RELEASE_READINESS.md).

## Development and validation

```powershell
python -m pip install pytest==9.1.1  # test-only dependency
python -m pytest -q
python -m compileall -q dwi scripts
python scripts\clean_env_smoke.py
python -m dwi evaluate-readonly --max-seconds 5 --max-nodes 2000 --max-files 2000
python -m dwi benchmark
```

Packaging and Windows build instructions are in
[docs/BUILD_WINDOWS.md](docs/BUILD_WINDOWS.md). Evaluation methodology is in
[docs/EVALUATION.md](docs/EVALUATION.md) and [docs/BENCHMARKS.md](docs/BENCHMARKS.md).
Contributors must follow [CONTRIBUTING.md](CONTRIBUTING.md). Security-sensitive
reports are described in [SECURITY.md](SECURITY.md).

When the repository is public, sensitive reports belong in GitHub Security —
Report a vulnerability / Security Advisories, not a public Issue. Enable
Private Vulnerability Reporting when publishing the repository; normal bugs
belong in regular Issues.

## Project status and license

The RC is prepared for independent public-release audit. It is not published
and does not imply that the final `1.0.0` release is authorized. The project
is distributed under the [MIT License](LICENSE). See
[CHANGELOG.md](CHANGELOG.md) for milestone history and RC notes.
