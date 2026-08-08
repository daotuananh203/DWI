# DWI Tasks

## Current state

The v0.1 Workspace Intelligence and v0.2 System Intelligence layers are
frozen. The v0.3 Safe Cleanup contract layer now defines immutable
engine-generated cleanup plans, immediate snapshot revalidation, and separate
execution authorization without implementing mutation.

All current behavior is covered by synthetic/tempdir and mocked-boundary
tests.

There is still no cleanup execution, UI, MCP adapter, LLM integration,
telemetry, cloud/API access, background service, or dynamic plugin system.
System scanning remains bounded, read-only, offline-first, and developer-storage
aware. Git remains structured protection/context only and is not a cleanup
candidate. Cleanup execution, Trash/Quarantine operations, journaling I/O, and
Undo operations remain unimplemented.

## Current milestone boundary

The v0.3 planning contract is implemented for pure domain operations only:
findings may become immutable proposals only with explicit engine-issued scan
context/root bindings, current snapshots may be compared with a new trusted
context, and authorization metadata may be issued only from engine-produced
validation proof. No executor or filesystem mutation exists.

## Next task — exactly one

- [ ] Implement isolated reversible Quarantine/Journal/Undo primitives against disposable test directories only.

### Acceptance criteria

- Restrict all mutation experiments to disposable synthetic test directories.
- Preserve recovery identifiers, audit records, replay safety, and fail-closed
  behavior; never mutate a user workspace.
- Keep execution separate from `CleanupPlan`, `PlanValidation`, and
  `ExecutionAuthorization`.
- Do not add permanent deletion, Desktop, MCP, i18n runtime, or dependencies.

Future work is described in [docs/ROADMAP.md](docs/ROADMAP.md), but it is not authorized by this task list.
