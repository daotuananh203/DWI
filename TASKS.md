# DWI Tasks

## Current state

v0.1 Workspace Intelligence, v0.2 System Intelligence, v0.3 Safe Cleanup,
the Windows Mutation Safety Gate, human-confirmed reversible cleanup, the
internal cleanup CLI, v0.4 Desktop, and v0.5 MCP / Agent Integration are
frozen. v1.0 hardening Batch 1/2 is implemented in the current working tree as
release-readiness engineering over the same deterministic engine.

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

## Current v1.0 hardening boundary

Batch 1/2 adds MCP resource limits and pagination, shared finite scan limits,
explicit safety/regression evidence, read-only machine evaluation, synthetic
benchmarks, single-source versioning, package metadata, Windows build
foundation, clean-environment smoke, and release-readiness documentation. It
does not add final installer branding, public publishing, or release polish.

## Next task — exactly one

- [ ] v1.0 Release Polish, Installer Validation, Documentation, and Final Public Release Audit.

### Acceptance criteria

- Complete final release polish, installer validation, documentation review,
  and public-release audit only after this batch is reviewed.
- Do not begin that task in the current batch.

### Recorded hardening evidence/debt

1. MCP caller cardinality and stdio message-size debts are closed in Batch 1/2.

### Mandatory v1.0 Batch 2 release blockers/debts

A. Package artifact build is not verified in the current environment because
   the `build` package is unavailable.
B. Wheel/sdist installation has not been verified in a clean environment.
C. Windows installer build and validation remain incomplete.
D. Signing strategy and status remain unresolved.
E. Open-source licensing and dependency-license review remain incomplete.
F. Final public EN/VI documentation remains incomplete.
G. Final public-release audit remains incomplete.
H. Direct `ScanLimits` accepts `0` and terminates immediately while MCP rejects
   `0`; this is conservative rather than fail-open and may be resolved or
   documented for public API consistency in Batch 2.

Future work in [docs/ROADMAP.md](docs/ROADMAP.md) is not authorized until this
is the single task in this file.
