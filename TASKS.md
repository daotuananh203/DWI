# DWI Tasks

## Current state

v0.1 Workspace Intelligence, v0.2 System Intelligence, v0.3 Safe Cleanup,
the Windows Mutation Safety Gate, human-confirmed reversible cleanup, and the
internal cleanup CLI are frozen. v0.4 Desktop is implemented as a native
Tkinter presentation/orchestration layer over the same deterministic engine.

Desktop provides system scan overview, findings filtering and explanations,
exact cleanup review, typed HumanConfirmation, fresh engine revalidation,
Quarantine + Journal + Undo outcomes, reconciliation-required handling,
background work/cancellation, EN/VI resources, and a deterministic
`python -m dwi desktop` entry point. Desktop does not contain a safety engine,
does not accept raw cleanup paths, and does not serialize trusted capabilities.

The product remains internal/pre-public. Cleanup means reversible same-volume
Quarantine + Journal + Undo; permanent deletion, telemetry, cloud/API access,
and network mutation are absent. Desktop v0.4 uses the trusted in-process
capability model. A stronger untrusted boundary is deferred to MCP.

## Current milestone boundary

The shared engine remains authoritative for evidence, interpretation,
RiskLabel, ActionEligibility, CleanupPlan, PlanValidation,
ExecutionAuthorization, mutation safety, journal state, reconciliation, and
recovery identity. Desktop only presents these values and orchestrates the
existing application/engine adapters. Incomplete, failed, denied, skipped, or
conflicting scan observations remain visibly partial or blocked. The Desktop
does not introduce persistence, a daemon, local RPC, cloud features, AI, or a
second mutation path.

## Next task — exactly one

- [ ] v0.5 MCP / Agent Integration with an explicit untrusted-interface boundary.

### Acceptance criteria

- Define and implement only opaque engine-issued handles for untrusted MCP
  requests; never accept arbitrary raw-path cleanup targets.
- Preserve the exact `Finding/SystemScan -> CleanupPlan -> Review ->
  HumanConfirmation -> fresh PlanValidation -> ExecutionAuthorization ->
  Quarantine -> Journal -> Undo` chain.
- Do not serialize or accept trusted capability/proof objects, and keep AI
  outside deterministic safety and authorization decisions.
- Preserve reconciliation fail-closed behavior, no permanent deletion,
  offline-first privacy, and network-mutation denial.

Future work in [docs/ROADMAP.md](docs/ROADMAP.md) is not authorized until this
is the single task in this file.
