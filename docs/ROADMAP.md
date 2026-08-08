# Roadmap

DWI evolves from a deterministic workspace analyzer into a full Developer
Storage Intelligence & Safe Cleanup System. Every milestone keeps the shared
evidence → interpretation → Safety Policy engine authoritative. v0.1 through
v0.5 are internal development milestones and are not public releases. The
repository is released publicly on GitHub only when v1.0.0 reaches the complete
North Star. Roadmap items do not authorize implementation until they become the
single task in `TASKS.md`.

## v0.1 — Workspace Intelligence

- Current CLI workspace analysis.
- Deterministic evidence, safety, and reporting.
- Internal milestone only; no public GitHub release.

Current v0.1 is analysis-and-reporting-only. It does not perform whole-system
scanning, cleanup planning, execution, Trash/Quarantine, Undo, Desktop, or MCP.

## v0.2 — System Intelligence

- Whole-system developer-storage discovery.
- Global caches and tool storage.
- Windows hardening.
- More ecosystems.

This remains an internal milestone; it is not a public release.

## v0.3 — Safe Cleanup

- `CleanupPlan`.
- Immediate filesystem/evidence revalidation.
- `ExecutionAuthorization`.
- Trash/Quarantine.
- Audit journal.
- Undo/recovery.
- Human confirmation.

This remains an internal milestone; it is not a public release.

`SAFE` and `ELIGIBLE_FOR_EXPLICIT_ACTION` will not independently authorize
execution. Permanent deletion remains out of scope until explicitly
authorized.

## v0.4 — Desktop

- Desktop UI over the same core engine.
- System overview.
- Findings and explanations.
- Cleanup-plan review.

This remains an internal milestone; it is not a public release.

## v0.5 — MCP / Agent Integration

Planned MCP operations:

- `scan_system`
- `explain_finding`
- `create_cleanup_plan`
- `review_cleanup_plan`
- `validate_cleanup_plan`
- `execute_cleanup_plan`
- `undo_cleanup`

MCP must never expose arbitrary raw-path deletion such as
`delete_file(path)`. Cleanup execution accepts only engine-generated plan and
plan-item identifiers after immediate revalidation and authorization.

This remains an internal milestone; it is not a public release.

## v1.0 — Public Complete

- Desktop + CLI + MCP.
- Windows whole-system developer-storage discovery.
- Deterministic evidence → interpretation → Safety Policy engine.
- Safe cleanup planning.
- Immediate revalidation and TOCTOU protection.
- `ExecutionAuthorization`.
- Trash/Quarantine.
- Audit journal.
- Undo/recovery.
- Windows installer/package.
- Real-world validation and benchmarks.
- Polished public documentation.
- English (`en`) and Vietnamese (`vi`) localization.

The v1.0.0 public release is allowed only when every item above is complete
and the complete North Star is reached. Desktop, CLI, and MCP must use the
same core Safety Policy engine.

## Cross-cutting safety direction

- Preserve deterministic observations → evidence → interpretation → Safety
  Policy.
- Keep `RiskLabel`, `ActionEligibility`, `CleanupPlan`, `PlanValidation`, and
  `ExecutionAuthorization` separate.
- Keep AI/LLM outside all safety and authorization decisions.
- Prefer Trash/Quarantine and auditable recovery over permanent deletion.

All roadmap items after the current task are future direction, not permission
to implement them.
