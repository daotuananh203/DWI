"""Internal engine adapters for the human cleanup workflow.

The CLI calls this module for engine-owned plan construction, fresh workspace
revalidation, and mutation-context provisioning. It never constructs trusted
scan contexts, snapshots, validation, authorization, or mutation capabilities
itself.
"""

from __future__ import annotations

import os
from datetime import datetime, timezone

from .application import (
    CleanupMutationContext,
    CleanupMutationProvider,
    EngineRevalidator,
    _engine_revalidator,
    _trusted_snapshot_set,
)
from .cleanup import (
    CleanupPlan,
    ExecutionAuthorization,
    FilesystemIdentity,
    PlanValidation,
    create_cleanup_plan,
    scan_context_from_system_scan,
    scan_context_from_workspace_scan,
    snapshot_from_finding,
    _path_is_within,
)
from .mutation import (
    MutationRefused,
    _observe_identity,
    approve_local_mutation_root,
    create_audit_journal,
    create_quarantine_root,
    inspect_quarantine_root,
    prepare_recovery_mutation_root,
    restore_recovery,
)
from .scanner import WorkspaceScan, scan_workspace
from .system_scan import SystemScan
from .pipeline import Finding


_ENGINE_VERSION = "dwi-cleanup-engine-v0.3"


def _path_key(path: str) -> str:
    return os.path.normcase(os.path.abspath(path))


def _planning_identities(scan: WorkspaceScan) -> dict[str, FilesystemIdentity]:
    identities: dict[str, FilesystemIdentity] = {}
    for finding in scan.findings:
        identity, reason = _observe_identity(finding.path)
        if identity is not None:
            identities[_path_key(finding.path)] = identity
        elif reason is not None:
            # Missing/invalid identity is deliberately omitted. The engine's
            # cleanup planner records the finding as an exclusion.
            continue
    return identities


def create_workspace_cleanup_plan(scan: WorkspaceScan) -> CleanupPlan:
    """Create a plan from one engine-produced workspace scan only."""

    if not isinstance(scan, WorkspaceScan):
        raise TypeError("workspace cleanup planning requires an engine WorkspaceScan")
    context = scan_context_from_workspace_scan(scan)
    if not context.approved_roots:
        raise ValueError("workspace scan did not produce an approved root")
    return create_cleanup_plan(
        scan.findings,
        filesystem_identities=_planning_identities(scan),
        scan_context=context,
        approved_root=context.approved_roots[0],
        engine_version=_ENGINE_VERSION,
    )


def create_system_cleanup_plan(
    scan: SystemScan,
    selected_findings: tuple[Finding, ...],
) -> CleanupPlan:
    """Create one engine-owned plan for selected findings under one root.

    Desktop selection is deliberately expressed as engine-produced ``Finding``
    objects, never as paths. A plan remains bound to one approved root; the
    caller must review roots independently when a system scan spans several
    roots. Completeness and eligibility checks remain in the pure planner.
    """

    if not isinstance(scan, SystemScan):
        raise TypeError("system cleanup planning requires an engine SystemScan")
    if not isinstance(selected_findings, tuple) or not selected_findings:
        raise ValueError("cleanup planning requires an explicit non-empty finding selection")
    if scan.termination.value != "completed" or scan.observation_failures or scan.ambiguous_boundaries:
        raise ValueError("incomplete system scan cannot produce an executable cleanup plan")
    source = {
        (_path_key(finding.path), finding.artifact): finding
        for finding in scan.findings
    }
    for finding in selected_findings:
        if source.get((_path_key(finding.path), finding.artifact)) != finding:
            raise ValueError("cleanup selection contains a finding outside the exact system scan")
    context = scan_context_from_system_scan(scan)
    if context.completeness.value != "complete" or not context.approved_roots:
        raise ValueError("system scan did not produce complete approved roots")
    roots = tuple(
        root for root in context.approved_roots
        if all(_path_is_within(finding.path, root.path) for finding in selected_findings)
    )
    if len(roots) != 1:
        raise ValueError("cleanup selection must belong to exactly one approved root")
    identities = {
        _path_key(finding.path): identity
        for finding in selected_findings
        for identity, reason in (_observe_identity(finding.path),)
        if identity is not None
    }
    return create_cleanup_plan(
        selected_findings,
        filesystem_identities=identities,
        scan_context=context,
        approved_root=roots[0],
        engine_version=_ENGINE_VERSION,
    )


def _fresh_workspace_snapshots(plan: CleanupPlan):
    scan = scan_workspace(plan.approved_root.path)
    context = scan_context_from_workspace_scan(scan)
    by_path = {_path_key(finding.path): finding for finding in scan.findings}
    snapshots = {}
    for item in plan.items:
        finding = by_path.get(_path_key(item.snapshot.path))
        if finding is None:
            raise MutationRefused("planned candidate was not found in the fresh engine scan")
        identity, reason = _observe_identity(finding.path)
        if identity is None:
            raise MutationRefused(reason or "fresh filesystem identity could not be observed")
        snapshots[item.plan_item_id] = snapshot_from_finding(
            finding,
            identity,
            canonical_path=item.snapshot.path,
        )
    return _trusted_snapshot_set(
        plan,
        snapshots,
        context,
        engine_version=_ENGINE_VERSION,
        created_at=datetime.now(timezone.utc).isoformat(),
    )


def _fresh_system_snapshots(plan: CleanupPlan):
    from .system_scan import SystemScanOptions, scan_system

    result = scan_system(SystemScanOptions(
        additional_roots=(plan.approved_root.path,),
        include_fixed_drives=False,
        include_user_profile=False,
        include_global_storage=False,
    ))
    context = scan_context_from_system_scan(result)
    by_path = {_path_key(finding.path): finding for finding in result.findings}
    snapshots = {}
    for item in plan.items:
        finding = by_path.get(_path_key(item.snapshot.path))
        if finding is None:
            raise MutationRefused("planned candidate was not found in the fresh engine scan")
        identity, reason = _observe_identity(finding.path)
        if identity is None:
            raise MutationRefused(reason or "fresh filesystem identity could not be observed")
        snapshots[item.plan_item_id] = snapshot_from_finding(
            finding,
            identity,
            canonical_path=item.snapshot.path,
        )
    return _trusted_snapshot_set(
        plan,
        snapshots,
        context,
        engine_version=_ENGINE_VERSION,
        created_at=datetime.now(timezone.utc).isoformat(),
    )


def workspace_engine_revalidator() -> EngineRevalidator:
    """Return an engine-owned revalidator that rescans the exact plan root."""

    return _engine_revalidator(_fresh_workspace_snapshots)


def system_engine_revalidator() -> EngineRevalidator:
    """Return an engine-owned revalidator for one system-scan plan."""

    return _engine_revalidator(_fresh_system_snapshots)


class WorkspaceCleanupRuntime:
    """One-process engine runtime for cleanup and immediate Undo."""

    def __init__(self) -> None:
        self._context: CleanupMutationContext | None = None
        self.provider = CleanupMutationProvider(self._recovery_context, self._authorized_context)

    def _recovery_context(self, plan: CleanupPlan) -> CleanupMutationContext:
        """Bind existing recovery state without creating mutation state.

        The application may subsequently append narrowly scoped reconciliation
        metadata for this pre-existing state. It may not create a quarantine
        root, claim, payload, or new cleanup lifecycle until authorization.
        """
        root = prepare_recovery_mutation_root(plan)
        quarantine = inspect_quarantine_root(root)
        journal = create_audit_journal(root)
        self._context = CleanupMutationContext(root, quarantine, journal)
        return self._context

    def _authorized_context(
        self,
        plan: CleanupPlan,
        validation: PlanValidation,
        authorization: ExecutionAuthorization,
    ) -> CleanupMutationContext:
        root = approve_local_mutation_root(plan, validation, authorization)
        quarantine = create_quarantine_root(root, create=True)
        journal = create_audit_journal(root)
        self._context = CleanupMutationContext(root, quarantine, journal)
        return self._context

    def undo(
        self,
        recovery_id: str,
        *,
        phase_callback=None,
        cancellation_checkpoint=None,
    ):
        if self._context is None:
            raise MutationRefused("Undo is available only within the active cleanup session")
        return restore_recovery(
            recovery_id,
            self._context.journal,
            self._context.mutation_root,
            self._context.quarantine_root,
            phase_callback=phase_callback,
            cancellation_checkpoint=cancellation_checkpoint,
        )

    def recovery_entries(self):
        """Return validated recovery state for the active in-process session."""

        if self._context is None or self._context.quarantine_root is None:
            return ()
        from .mutation import reconcile_pending_operations

        return reconcile_pending_operations(
            self._context.journal,
            self._context.mutation_root,
            self._context.quarantine_root,
        )


def workspace_mutation_runtime() -> WorkspaceCleanupRuntime:
    """Return the internal one-process runtime used by the CLI application."""

    return WorkspaceCleanupRuntime()
