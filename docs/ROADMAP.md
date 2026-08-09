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

- Bounded developer-storage discovery across approved local fixed drives,
  profile locations, explicit local roots, and known tool-specific caches.
- Scan Safety Gate with network default deny, no link/reparse traversal,
  deterministic cancellation, traversal limits, and partial results.
- Global pip, uv, npm, pnpm, and yarn cache analysis where local structure is
  defensible.
- `scan-system` CLI and JSON reporting over the existing safety engine.
- Offline-first, read-only behavior with no telemetry, automatic upload,
  HTTP, cloud, or API communication. Network filesystem access remains denied
  by default and requires explicit opt-in.

This remains an internal milestone; it is not a public release.

The v0.2 implementation remains intentionally bounded. It does not perform
cleanup, project-wide reachability, process-wide activity analysis, background
service work, or network discovery by default.

## v0.3 — Safe Cleanup

- Immutable engine-generated `CleanupPlan` and plan-item snapshots.
- Immediate filesystem/evidence `PlanValidation`.
- Separate metadata-only `ExecutionAuthorization`.
- Typed `RecoveryMetadata` and `QuarantineRecord` contracts.
- Isolated reversible Quarantine/Journal/Undo primitives guarded by either an
  explicitly marked disposable test directory or an internal approved-local
  Windows root capability derived from the exact authorized plan.
- Journal chain integrity with explicit post-rename recovery states and
  conservative restart reconciliation.
- Internal presentation-neutral human-confirmed Cleanup Application Service
  with exact review binding, post-confirmation revalidation, per-item results,
  and conservative orphan-claim recovery.
- Internal human-facing CLI adapter over that service, with exact confirmation,
  deterministic table/JSON review, explicit exit states, quarantine/journal,
  and same-process Undo by recovery identifier.
- No public release, MCP cleanup interface, permanent deletion,
  Windows Recycle Bin integration, cross-process capability persistence, or
  arbitrary raw-path mutation API.

This remains an internal milestone; it is not a public release.

`SAFE` and `ELIGIBLE_FOR_EXPLICIT_ACTION` do not independently authorize
execution. Desktop v0.4 is a native Tkinter presentation/orchestration layer
over the same engine and application service. Permanent deletion remains out
of scope until explicitly authorized.

## v0.4 — Desktop

- Native stdlib Tkinter Desktop over the same core engine and application
  service.
- System scan overview with roots, partial/failed/denied boundaries, limits,
  cancellation, known/partial/reclaimable byte accounting, and Git context.
- Findings dashboard with RiskLabel/ActionEligibility separation,
  filtering/sorting/search, size completeness, and structured explanations.
- Exact CleanupSession/HumanConfirmation review, fresh engine revalidation,
  Quarantine + Journal + Undo outcomes, reconciliation-required UX, and
  recovery identity listing.
- Explicit controller/state model, one-worker background boundary, EN/VI
  packaged resources, deterministic desktop entry point, and disposable-fixture
  developer smoke path.
- Trusted in-process capability model only; no serialized capabilities, MCP,
  telemetry, cloud/API calls, or permanent deletion.

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
