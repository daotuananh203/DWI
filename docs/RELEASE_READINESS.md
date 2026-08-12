# v1.0 Release Readiness Evidence

This document tracks readiness evidence for the v1.0.0 stable release.

## Current gate status

| Gate | Status | Evidence or remaining boundary |
|---|---|---|
| Version source | PASS | Single source `dwi/version.py` reports `1.0.0`. |
| Canonical full test suite | PASS | Fresh venv with pytest 9.1.1; `python -m pytest -q`: 288 passed, 0 skipped, 103 subtests passed. |
| MCP and v1 hardening tests | PASS | MCP 29 passed; v1 hardening 5 passed; evaluation/benchmark 2 passed. |
| Python compilation and diff hygiene | PASS | `compileall` and `git diff --check` pass. |
| Wheel and sdist | PASS | `dwi-1.0.0-py3-none-any.whl` and `dwi-1.0.0.tar.gz` built; hashes are in `RELEASE_ARTIFACTS.md`. |
| Clean wheel install | PASS | Fresh venv imports from `site-packages`; CLI/MCP smoke pass. |
| Clean sdist install | PASS | Fresh venv built and installed the sdist; CLI/MCP smoke pass. |
| Windows Desktop artifact | PASS | PyInstaller produced Desktop EXE (`DWI-1.0.0-Desktop.exe`) and portable `windows-x64` ZIP; startup smoke pass. |
| Windows installer runtime | NOT VERIFIED | Inno Setup (`ISCC.exe`) is unavailable on host machine; installer build NOT VERIFIED. |
| Signing | PASS BY POLICY | **UNSIGNED — ACCEPTED BY RELEASE POLICY**; EXE/installer are disclosed and checksummed, Windows SmartScreen may warn, and no trusted certificate claim is made. |
| License and dependency audit | PASS | MIT project license, build-tool metadata, and verified Inno Setup License/output distribution conclusion are recorded in `DEPENDENCY_LICENSES.md`. |
| Security reporting channel | PASS | `SECURITY.md` defines Private Vulnerability Reporting instructions. |
| EN/VI public documentation | PASS | English README/docs and Vietnamese README counterpart are included. |
| Read-only evaluation | PASS | Real Windows run: mutation `false`, network `false`, bounded at 2,000 nodes. |
| Synthetic benchmark | PASS | Scales 10/100/500 completed with bounded metrics and no private fixture paths recorded. |
| Safety/privacy/hygiene audit | PASS | No runtime permanent delete, raw-path MCP mutation, telemetry, cloud/API, or default listener found. |
| Fault/restart evidence | PASS | Existing fault/reconciliation tests pass. |
| Public release authorization | PASS | Authorization granted for 1.0.0 stable release. |

The checked statuses describe this local RC validation record only. They do not
claim code signing, public distribution, or final release approval.

## Canonical test command

The authoritative RC test command is `python -m pytest -q`, run from the RC
source tree with pytest 9.1.1 installed in a fresh isolated environment. This
run produced `288 passed, 0 skipped, 103 subtests passed`. The older unittest
cross-check reported 275 discovered test methods because it counts six
unittest methods containing subtests differently; it is not the release count.

## Skipped-test audit

Current skips are platform capability conditions, not hidden safety failures:

- Windows mutation/application integration tests require `os.name == "nt"`.
- Symlink/reparse tests skip only when the host cannot create the required
  fixture; Windows-capable CI/manual evaluation must run them.
- No skipped test authorizes mutation or weakens the deterministic policy path.

## Existing fault/recovery evidence

The frozen mutation/application suite already exercises claim failure, orphan
claims, committed-but-unjournaled quarantine/restore, partial multi-item
execution, unexpected item failure, journal corruption, replay, and idempotent
reconciliation. Any release claim remains limited to those tested filesystem
semantics; this checklist does not claim crash-proof atomic transactions.

## Release-candidate status

Batch 2 records concrete status for wheel/sdist, Desktop, installer, signing,
license, documentation, privacy and repository hygiene. Public-release
authorization remains intentionally outside this implementation batch. The
status table above is the release-candidate evidence gate; the `BLOCKED`
authorization entry is not a claim of final release readiness.
