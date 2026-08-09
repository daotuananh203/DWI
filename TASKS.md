# DWI Tasks

## Current state

The v0.1 Workspace Intelligence and v0.2 System Intelligence layers are
frozen. The v0.3 Safe Cleanup contract layer defines immutable engine-generated
cleanup plans, immediate snapshot revalidation, separate execution
authorization, a real-Windows Mutation Safety Gate, and reversible
quarantine/journal primitives.

All current behavior is covered by synthetic/tempdir and mocked-boundary
tests.

There is still no public user-workspace cleanup executor, UI, MCP adapter, LLM integration,
telemetry, cloud/API access, background service, or dynamic plugin system.
System scanning remains bounded, read-only, offline-first, and developer-storage
aware. Git remains structured protection/context only and is not a cleanup
candidate. No public cleanup interface or permanent deletion exists; mutation
is internal and requires the disposable-root boundary or the new engine-issued
approved-local-root gate.

## Current milestone boundary

The v0.3 planning contract remains pure for plan creation, validation, and
authorization: findings may become immutable proposals only with explicit
engine-issued scan context/root bindings, current snapshots may be compared
with a new trusted context, and authorization metadata may be issued only from
engine-produced validation proof. Mutation additionally requires exact
validated snapshots, a private one-shot authorization item, an approved local
root, authoritative Windows final-path identity, and immediate
identity/type/reparse/path revalidation. Authorization claims are established
before mutation lifecycle records are written. The internal presentation-neutral
application service adds exact review, human confirmation, fresh revalidation,
and per-item execution reporting without widening the public surface. Valid
orphan claims are journaled as claimed and failed without mutation during
restart reconciliation; malformed or unjournalable claims remain blocked and
require review. Claim files are retained as replay locks.

Orphan claim files after a crash before `AUTHORIZATION_CLAIMED` are detected
during restart reconciliation. Valid claims are journaled as claimed and
failed without mutation; malformed or unjournalable claims remain blocked.

## Next task — exactly one

- [ ] Directly audit the complete end-to-end cleanup application flow before exposing any cleanup interface.

### Acceptance criteria

- Audit the complete `Finding/SystemScan -> CleanupPlan -> Review ->
  HumanConfirmation -> fresh PlanValidation -> ExecutionAuthorization ->
  Quarantine -> Journal -> Undo` flow, including exact binding and failure
  semantics.
- Do not expose mutation through the public CLI, Desktop, MCP, or arbitrary raw
  paths; preserve the `CleanupPlan` -> `PlanValidation` ->
  `ExecutionAuthorization` chain.
- Do not add permanent deletion, user-workspace cleanup, i18n runtime, or
  dependencies.

Future work is described in [docs/ROADMAP.md](docs/ROADMAP.md), but it is not authorized by this task list.
