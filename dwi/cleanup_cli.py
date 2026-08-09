"""Human-facing, presentation-only cleanup workflow for the internal CLI."""

from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from enum import IntEnum
from typing import Any, Callable

from .application import (
    CleanupApplicationResult,
    CleanupItemOutcome,
    CleanupSessionState,
    create_cleanup_session,
    create_human_confirmation,
    execute_cleanup_session,
)
from .cleanup import CleanupPlan, QuarantineState
from .cleanup_engine import (
    WorkspaceCleanupRuntime,
    create_workspace_cleanup_plan,
    workspace_engine_revalidator,
    workspace_mutation_runtime,
)
from .mutation import MutationRefused
from .report import _json_value, scan_to_dict, table_report
from .scanner import WorkspaceScan, WorkspaceScanError, scan_workspace


CONFIRMATION_PHRASE = "I reviewed this exact cleanup plan."


class CleanupExitCode(IntEnum):
    SUCCESS = 0
    CANCELLED = 1
    INVALID_STATE = 2
    BLOCKED = 3
    PARTIAL = 4
    RECOVERY_FAILURE = 5
    INTERNAL_ERROR = 6


def _path_key(path: str) -> str:
    return path.casefold()


def _finding_by_path(scan: WorkspaceScan) -> dict[str, object]:
    return {_path_key(finding.path): finding for finding in scan.findings}


def _review_dict(scan: WorkspaceScan, plan: CleanupPlan, session_id: str) -> dict[str, Any]:
    findings = _finding_by_path(scan)
    items: list[dict[str, Any]] = []
    for item in plan.items:
        snapshot = item.snapshot
        finding = findings.get(_path_key(snapshot.path))
        items.append({
            "plan_item_id": item.plan_item_id.value,
            "artifact": snapshot.artifact.value,
            "path": snapshot.path,
            "size": {
                "known_bytes": snapshot.size.known_bytes,
                "complete": snapshot.size.complete,
                "observation_failures": list(snapshot.size.observation_failures),
            },
            "risk_label": snapshot.risk_label.value,
            "action_eligibility": snapshot.action_eligibility.value,
            "provenance": _json_value(snapshot.provenance),
            "regenerability": snapshot.regenerability.value,
            "regeneration_cost": snapshot.regeneration_cost.value,
            "reachability": snapshot.reachability.value,
            "activity": snapshot.activity.value,
            "protection": snapshot.protection.value,
            "evidence": _json_value(snapshot.evidence),
            "safety_decision": _json_value(finding.safety_decision) if finding is not None else None,
            "rule_trace": _json_value(snapshot.rule_trace),
            "summary": finding.summary if finding is not None else None,
        })
    return {
        "session_id": session_id,
        "plan_id": plan.plan_id.value,
        "engine_version": plan.engine_version,
        "approved_root": plan.approved_root.path,
        "items": items,
        "exclusions": [
            {
                "artifact": exclusion.artifact.value,
                "path": exclusion.path,
                "reason": exclusion.reason,
            }
            for exclusion in plan.exclusions
        ],
    }


def _result_dict(result: CleanupApplicationResult) -> dict[str, Any]:
    return {
        "session_id": result.session_id,
        "plan_id": result.plan_id.value,
        "state": result.state.value,
        "validation_status": result.validation_status.value if result.validation_status is not None else None,
        "authorization_status": result.authorization_status.value if result.authorization_status is not None else None,
        "transactional": result.transactional,
        "reason": result.reason,
        "item_results": [
            {
                "plan_item_id": item.plan_item_id.value,
                "outcome": item.outcome.value,
                "quarantine_state": item.quarantine_state.value if item.quarantine_state is not None else None,
                "recovery_id": item.recovery_id,
                "reason": item.reason,
            }
            for item in result.item_results
        ],
        "reconciliation": (
            {
                "failures": list(result.reconciliation.failures),
                "metadata_appended": result.reconciliation.metadata_appended,
                "claim_recoveries": [
                    {
                        "claim_path": recovery.claim_path,
                        "plan_id": recovery.plan_id,
                        "plan_item_id": recovery.plan_item_id,
                        "state": recovery.state.value,
                        "reason": recovery.reason,
                    }
                    for recovery in result.reconciliation.claim_recoveries
                ],
            }
            if result.reconciliation is not None
            else None
        ),
    }


def _review_human(scan: WorkspaceScan, plan: CleanupPlan, session_id: str) -> None:
    print("Cleanup review")
    print(table_report(scan), end="")
    print(f"Session: {session_id}")
    print(f"Executable plan items: {len(plan.items)}")
    if plan.items:
        print("Only these engine-selected items can be quarantined:")
        findings = _finding_by_path(scan)
        for item in plan.items:
            snapshot = item.snapshot
            finding = findings.get(_path_key(snapshot.path))
            size_state = "complete" if snapshot.size.complete else "partial/incomplete"
            print(
                f"- {item.plan_item_id.value}: {snapshot.path} "
                f"[{snapshot.risk_label.value}, {snapshot.action_eligibility.value}]"
            )
            print(f"  size: {snapshot.size.known_bytes} bytes ({size_state})")
            print(f"  provenance: {json.dumps(_json_value(snapshot.provenance), sort_keys=True)}")
            print(f"  regenerability: {snapshot.regenerability.value} ({snapshot.regeneration_cost.value} cost)")
            print(f"  reachability: {snapshot.reachability.value}")
            print(f"  activity: {snapshot.activity.value}")
            print(f"  protection: {snapshot.protection.value}")
            print(f"  evidence: {json.dumps(_json_value(snapshot.evidence), sort_keys=True)}")
            print(f"  safety decision: {json.dumps(_json_value(finding.safety_decision) if finding is not None else None, sort_keys=True)}")
            print(f"  rule trace: {json.dumps(_json_value(snapshot.rule_trace), sort_keys=True)}")
            if finding is not None:
                print(f"  summary: {finding.summary}")
    if plan.exclusions:
        print("Excluded findings:")
        for exclusion in plan.exclusions:
            print(f"- {exclusion.path}: {exclusion.reason}")
    print("Execution uses same-volume quarantine, journaled recovery, and Undo; it never permanently deletes data.")


def _review_json(scan: WorkspaceScan, plan: CleanupPlan, session_id: str) -> str:
    return json.dumps({
        "schema": "dwi.cleanup.v0.1",
        "command": "cleanup",
        "state": "review_ready" if plan.items else "no_executable_items",
        "review": _review_dict(scan, plan, session_id),
        "scan": scan_to_dict(scan),
    }, indent=2, sort_keys=True) + "\n"


def _application_exit_code(result: CleanupApplicationResult) -> CleanupExitCode:
    if result.state is CleanupSessionState.EXECUTED:
        return CleanupExitCode.SUCCESS
    if result.state is CleanupSessionState.PARTIAL:
        return CleanupExitCode.PARTIAL
    if result.state is CleanupSessionState.RECONCILIATION_REQUIRED:
        return CleanupExitCode.RECOVERY_FAILURE
    return CleanupExitCode.BLOCKED


def _result_json(scan: WorkspaceScan, plan: CleanupPlan, result: CleanupApplicationResult) -> str:
    return json.dumps({
        "schema": "dwi.cleanup.v0.1",
        "command": "cleanup",
        "state": result.state.value,
        "review": _review_dict(scan, plan, result.session_id),
        "scan": scan_to_dict(scan),
        "result": _result_dict(result),
    }, indent=2, sort_keys=True) + "\n"


def _cancelled(as_json: bool, reason: str = "cleanup cancelled") -> int:
    if as_json:
        print(json.dumps({
            "schema": "dwi.cleanup.v0.1",
            "command": "cleanup",
            "state": "cancelled",
            "reason": reason,
        }, indent=2, sort_keys=True))
    else:
        print(reason, file=sys.stderr)
    return int(CleanupExitCode.CANCELLED)


def _restore_human(runtime: WorkspaceCleanupRuntime, recovery_id: str) -> CleanupExitCode:
    try:
        restored = runtime.undo(recovery_id)
    except (MutationRefused, OSError, ValueError) as error:
        print(f"Undo failed: {error}", file=sys.stderr)
        return CleanupExitCode.RECOVERY_FAILURE
    if restored.state is QuarantineState.RESTORED:
        print(f"Restored: {recovery_id}")
        return CleanupExitCode.SUCCESS
    print(
        f"Undo {restored.state.value}: {restored.failure_reason or 'recovery requires review'}",
        file=sys.stderr,
    )
    return CleanupExitCode.RECOVERY_FAILURE


def run_cleanup(
    root: str,
    *,
    as_json: bool = False,
    confirmation_phrase: str | None = None,
    input_fn: Callable[[str], str] = input,
) -> int:
    """Run one complete cleanup review/execution/optional-Undo session."""

    try:
        scan = scan_workspace(root)
        plan = create_workspace_cleanup_plan(scan)
        session = create_cleanup_session(plan)
    except KeyboardInterrupt:
        return _cancelled(as_json)
    except (WorkspaceScanError, MutationRefused, OSError, ValueError) as error:
        if as_json:
            print(json.dumps({
                "schema": "dwi.cleanup.v0.1",
                "command": "cleanup",
                "state": "invalid",
                "reason": str(error),
            }, indent=2, sort_keys=True))
        else:
            print(f"dwi: cleanup could not start: {error}", file=sys.stderr)
        return int(CleanupExitCode.INVALID_STATE)

    if as_json:
        if not plan.items:
            try:
                print(_review_json(scan, plan, session.session_id), end="")
            except KeyboardInterrupt:
                return _cancelled(as_json)
            return int(CleanupExitCode.SUCCESS)
    else:
        try:
            _review_human(scan, plan, session.session_id)
        except KeyboardInterrupt:
            return _cancelled(as_json)
        if not plan.items:
            return int(CleanupExitCode.SUCCESS)

    phrase = confirmation_phrase
    if phrase is None and not as_json:
        try:
            phrase = input_fn(f'Type exactly "{CONFIRMATION_PHRASE}" to continue: ')
        except KeyboardInterrupt:
            return _cancelled(as_json)
        except EOFError:
            phrase = None
    if phrase != CONFIRMATION_PHRASE:
        reason = "cleanup cancelled: exact human confirmation was not provided"
        if as_json:
            print(json.dumps({
                "schema": "dwi.cleanup.v0.1",
                "command": "cleanup",
                "state": "cancelled",
                "reason": reason,
                "review": _review_dict(scan, plan, session.session_id),
            }, indent=2, sort_keys=True))
        else:
            print(reason, file=sys.stderr)
        return int(CleanupExitCode.CANCELLED)

    try:
        confirmation = create_human_confirmation(
            session,
            session.review,
            confirmation_phrase=phrase,
            confirmed_at=datetime.now(timezone.utc).isoformat(),
        )
        runtime = workspace_mutation_runtime()
        result = execute_cleanup_session(
            session,
            confirmation,
            engine_revalidator=workspace_engine_revalidator(),
            mutation_provider=runtime.provider,
        )
    except KeyboardInterrupt:
        return _cancelled(as_json)
    except Exception as error:
        if as_json:
            print(json.dumps({
                "schema": "dwi.cleanup.v0.1",
                "command": "cleanup",
                "state": "internal_error",
                "reason": "cleanup failed closed",
            }, indent=2, sort_keys=True))
        else:
            print(f"dwi: cleanup failed closed: {error}", file=sys.stderr)
        return int(CleanupExitCode.INTERNAL_ERROR)

    if as_json:
        print(_result_json(scan, plan, result), end="")
        return int(_application_exit_code(result))

    print(f"Cleanup result: {result.state.value}")
    if result.reason:
        print(f"Reason: {result.reason}")
    for item in result.item_results:
        recovery = f" recovery={item.recovery_id}" if item.recovery_id else ""
        print(f"- {item.plan_item_id.value}: {item.outcome.value}{recovery}")
    recoveries = tuple(
        item.recovery_id
        for item in result.item_results
        if item.recovery_id is not None and item.outcome in {CleanupItemOutcome.SUCCEEDED, CleanupItemOutcome.RECOVERABLE}
    )
    if recoveries:
        try:
            undo_id = input_fn("Enter one recovery ID to Undo now, or press Enter to finish: ").strip()
        except KeyboardInterrupt:
            print("cleanup interrupted after mutation; journal/recovery state was preserved", file=sys.stderr)
            return int(CleanupExitCode.RECOVERY_FAILURE)
        except EOFError:
            undo_id = ""
        if undo_id:
            try:
                return int(_restore_human(runtime, undo_id))
            except KeyboardInterrupt:
                print("cleanup interrupted after mutation; journal/recovery state was preserved", file=sys.stderr)
                return int(CleanupExitCode.RECOVERY_FAILURE)
    return int(_application_exit_code(result))
