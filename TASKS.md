# DWI Tasks

## Current state

v0.1 Workspace Intelligence, v0.2 System Intelligence, v0.3 Safe Cleanup,
the Windows Mutation Safety Gate, human-confirmed reversible cleanup, the
internal cleanup CLI, v0.4 Desktop, and v0.5 MCP / Agent Integration are
frozen. v1.0 Batch 1/2 is prepared as a `1.0.0rc1` release candidate over the
same deterministic engine; public release is not authorized.

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

## Current v1.0 release-candidate boundary

Batch 1/2 adds MCP resource limits and pagination, shared finite scan limits,
explicit safety/regression evidence, read-only machine evaluation, synthetic
benchmarks, single-source versioning, package metadata, Windows build
foundation, clean-environment smoke, public EN/VI documentation, licensing,
artifact validation and release-readiness tracking. It does not authorize final
`1.0.0`, tagging, publishing or public release.

## Next task — exactly one

- [ ] Final independent v1.0 public-release audit and release authorization.

### Acceptance criteria

- Review the complete `1.0.0rc1` artifact, installer, documentation, safety,
  privacy and repository evidence.
- Authorize final `1.0.0` only after the independent audit passes.

### Recorded release-candidate evidence

1. MCP caller cardinality and stdio message-size debts are closed.
2. Public caller-created scan limits are finite, positive and hard-bounded.
3. Artifact, installer, signing, license, documentation and final-audit status
   are recorded in `docs/RELEASE_READINESS.md`.

Future work in [docs/ROADMAP.md](docs/ROADMAP.md) is not authorized until this
is the single task in this file.
