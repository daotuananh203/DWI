# Contributing

Use Python 3.11+ on Windows for the supported mutation and Desktop paths.
Create an isolated environment for development and build tools. Runtime code
must remain dependency-light and offline-first.

Before opening a change:

```powershell
python -m pip install pytest==9.1.1  # test-only dependency
python -m pytest -q
python -m compileall -q dwi scripts
git diff --check
```

Safety changes require regression tests and a documentation update. Preserve
the evidence → interpretation → Safety Policy separation. Do not let an AI
model manufacture `RiskLabel`, `ActionEligibility`, validation,
authorization, trusted snapshots or human confirmation.

All mutation tests use disposable temporary directories or the explicitly
marked engine test-root capabilities. Never point mutation tests at a real
workspace, user profile or untracked data. Keep Quarantine + Journal + Undo
reversible and preserve reconciliation behavior.

Keep MCP schemas strict: no raw-path mutation, no caller-created authority,
no confirmation phrase from the agent, bounded inputs, bounded messages and
server-owned opaque handles. Keep Desktop cancellation and close-window
semantics aligned with the worker/core phase boundary.

Pull requests should explain scope, tests, safety impact, documentation impact,
and any platform-specific skips. Do not commit generated wheels, installers,
executables, archives, virtual environments, caches, journals or private
evaluation output.
