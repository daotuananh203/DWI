# DWI Tasks

## Current state

v0.1 Workspace Intelligence, v0.2 System Intelligence, v0.3 Safe Cleanup,
the Windows Mutation Safety Gate, human-confirmed reversible cleanup, and the
internal cleanup CLI, and v0.4 Desktop are frozen. v0.5 MCP / Agent Integration
is implemented as a local-only untrusted JSON-RPC adapter over the same
deterministic engine.

Desktop provides system scan overview, findings filtering and explanations,
exact cleanup review, typed HumanConfirmation, fresh engine revalidation,
Quarantine + Journal + Undo outcomes, reconciliation-required handling,
background work/cancellation, EN/VI resources, and a deterministic
`python -m dwi desktop` entry point. Desktop does not contain a safety engine,
does not accept raw cleanup paths, and does not serialize trusted capabilities.

MCP exposes read-only scan/explanation tools plus opaque-handle cleanup review,
trusted-human-confirmation gating, fresh-revalidated execution, recovery
status, and recovery-handle Undo. MCP does not accept arbitrary mutation paths,
agent confirmation text, safety decisions, engine proofs, or serialized
capabilities. Authority-bearing handles are in-memory only and invalid after
server restart.

The product remains internal/pre-public. Cleanup means reversible same-volume
Quarantine + Journal + Undo; permanent deletion, telemetry, cloud/API access,
and network mutation are absent. Desktop v0.4 retains its trusted in-process
capability model; MCP v0.5 adds an explicit untrusted boundary.

## Current milestone boundary

The shared engine remains authoritative for evidence, interpretation,
RiskLabel, ActionEligibility, CleanupPlan, PlanValidation,
ExecutionAuthorization, mutation safety, journal state, reconciliation, and
recovery identity. Desktop only presents these values and orchestrates the
existing application/engine adapters. Incomplete, failed, denied, skipped, or
conflicting scan observations remain visibly partial or blocked. The Desktop
and MCP adapters do not introduce persistence, a daemon, cloud features, AI
safety decisions, or a second mutation path. MCP uses local stdin/stdout only
and has no TCP/HTTP listener.

## Next task — exactly one

- [ ] v1.0 hardening, packaging, evaluation, documentation, and public-release readiness.

### Acceptance criteria

- Harden and evaluate the frozen v0.1-v0.5 system before any public release.
- Do not begin this task in the current milestone.

### Recorded v1.0 hardening debt

1. Add explicit maximum item counts/request-cardinality bounds for caller
   arrays such as MCP `roots` and `finding_ids`.
2. Add an explicit maximum request/message size to the MCP stdio transport.

Future work in [docs/ROADMAP.md](docs/ROADMAP.md) is not authorized until this
is the single task in this file.
