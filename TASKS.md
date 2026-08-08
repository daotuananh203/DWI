# DWI Tasks

## Current state

The v0.1 Workspace Intelligence and v0.2 System Intelligence layers are
frozen. The v0.3 Safe Cleanup contract layer defines immutable engine-generated
cleanup plans, immediate snapshot revalidation, separate execution
authorization, and isolated reversible mutation primitives restricted to
explicitly marked disposable temporary roots.

All current behavior is covered by synthetic/tempdir and mocked-boundary
tests.

There is still no user-workspace cleanup executor, UI, MCP adapter, LLM integration,
telemetry, cloud/API access, background service, or dynamic plugin system.
System scanning remains bounded, read-only, offline-first, and developer-storage
aware. Git remains structured protection/context only and is not a cleanup
candidate. No public cleanup interface or permanent deletion exists; the
internal disposable-root primitive is the only mutation path.

## Current milestone boundary

The v0.3 planning contract remains pure for plan creation, validation, and
authorization: findings may become immutable proposals only with explicit
engine-issued scan context/root bindings, current snapshots may be compared
with a new trusted context, and authorization metadata may be issued only from
engine-produced validation proof. The separate mutation primitive accepts only
an exact authorized plan and an engine-issued disposable-root capability.

## Next task — exactly one

- [ ] Perform Mutation Safety Gate audit and harden real Windows Trash/Quarantine integration before any public cleanup interface.

### Acceptance criteria

- Review the disposable-root guard, immediate identity/reparse revalidation,
  same-filesystem non-overwriting rename, chained journal integrity,
  post-rename journal-failure states, crash-window reconciliation, partial
  failure, and idempotent Undo behavior on real Windows semantics.
- Do not expose mutation through the public CLI, Desktop, MCP, or arbitrary raw
  paths; preserve the `CleanupPlan` -> `PlanValidation` ->
  `ExecutionAuthorization` chain.
- Do not add permanent deletion, user-workspace cleanup, i18n runtime, or
  dependencies.

Future work is described in [docs/ROADMAP.md](docs/ROADMAP.md), but it is not authorized by this task list.
