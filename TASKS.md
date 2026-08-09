# DWI Tasks

## Current state

The v0.1 Workspace Intelligence and v0.2 System Intelligence layers are
frozen. The v0.3 Safe Cleanup contract layer defines immutable engine-generated
cleanup plans, immediate snapshot revalidation, separate execution
authorization, a real-Windows Mutation Safety Gate, and reversible
quarantine/journal primitives.

All current behavior is covered by synthetic/tempdir and mocked-boundary
tests.

The internal human-facing CLI now adapts the reviewed cleanup flow in one
process. It is not a public release or a public general user-workspace
executor, and
there is still no Desktop or MCP adapter, LLM integration, telemetry,
cloud/API access, background service, or dynamic plugin system. The CLI does
not persist or accept engine capabilities across processes.
System scanning remains bounded, read-only, offline-first, and developer-storage
aware. Git remains structured protection/context only and is not a cleanup
candidate. No public cleanup release or Desktop/MCP cleanup interface exists;
permanent deletion is absent. Mutation is internal and requires the disposable-root boundary or the new engine-issued
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
and per-item execution reporting. The CLI only presents and orchestrates this
service; it cannot construct trusted scan state, validation, authorization, or
raw-path mutation requests. Valid
orphan claims are journaled as claimed and failed without candidate or
quarantine-payload mutation during restart reconciliation; malformed or
unjournalable claims remain blocked and require review. Claim files are
retained as replay locks. This pre-authorization reconciliation may append
metadata for pre-existing DWI recovery state, but it cannot begin a new
cleanup lifecycle or issue new authorization in the same invocation.

Orphan claim files after a crash before `AUTHORIZATION_CLAIMED` are detected
during restart reconciliation. Valid claims are journaled as claimed and
failed by append-only metadata reconciliation without candidate or payload
mutation; malformed or unjournalable claims remain blocked. A new cleanup
authorization is not requested in that same invocation.

## Next task — exactly one

- [ ] Directly audit the human CLI cleanup flow before beginning Desktop integration.

### Acceptance criteria

- Audit the CLI `Finding/SystemScan -> CleanupPlan -> Review ->
  HumanConfirmation -> fresh PlanValidation -> ExecutionAuthorization ->
  Quarantine -> Journal -> Undo` flow, including output, exit states, exact
  binding, one-process capability boundaries, and failure semantics.
- Ensure the CLI remains presentation/orchestration only: no raw mutation path,
  trusted state, validation, authorization, unsafe confirmation flag, or
  cross-process capability serialization may enter through it. Preserve the
  `CleanupPlan` -> `PlanValidation` -> `ExecutionAuthorization` chain.
- Do not add permanent deletion, user-workspace cleanup, i18n runtime, or
  dependencies.

Future work is described in [docs/ROADMAP.md](docs/ROADMAP.md), but it is not authorized by this task list.
