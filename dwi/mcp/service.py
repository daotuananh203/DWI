"""Untrusted MCP orchestration over the existing deterministic DWI engine."""

from __future__ import annotations

import hashlib
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable

from ..application import (
    CleanupApplicationResult,
    CleanupItemOutcome,
    CleanupSession,
    CleanupSessionState,
    HumanConfirmation,
    create_cleanup_session,
    create_human_confirmation,
    execute_cleanup_session,
)
from ..cleanup import QuarantineState
from ..cleanup_engine import (
    WorkspaceCleanupRuntime,
    create_system_cleanup_plan,
    system_engine_revalidator,
    workspace_mutation_runtime,
)
from ..cleanup_cli import CONFIRMATION_PHRASE
from ..mutation import RestoreResult
from ..pipeline import Finding
from ..report import _json_value, finding_to_dict, system_to_dict
from ..scan_control import ScanLimits
from ..system_scan import SystemScan, SystemScanOptions, scan_system
from .models import McpErrorCode, McpHandleState, McpHandleType, McpServiceError
from .schemas import (
    MCP_DEFAULT_MAX_FILES,
    MCP_DEFAULT_MAX_NODES,
    MCP_DEFAULT_MAX_SECONDS,
    TOOL_DEFINITIONS,
    validate_arguments,
    validate_scan_budget,
)
from .state_store import OpaqueHandleStore


@dataclass
class _ScanState:
    scan: SystemScan
    findings: dict[str, Finding]


@dataclass
class _ReviewState:
    scan_handle: str
    scan: SystemScan
    plan: object
    session: CleanupSession
    confirmation: HumanConfirmation | None = None
    execution_handle: str | None = None


@dataclass
class _ExecutionState:
    review_handle: str
    review: _ReviewState
    runtime: WorkspaceCleanupRuntime | None = None
    result: CleanupApplicationResult | None = None
    status: str = McpHandleState.READY_FOR_EXECUTION.value
    error: str | None = None
    recovery_handles: list[str] = field(default_factory=list)


@dataclass
class _RecoveryState:
    execution_handle: str
    runtime: WorkspaceCleanupRuntime
    recovery_id: str
    result: RestoreResult | None = None


class _TrustedHumanChannel:
    """Opaque in-process token held only by a trusted human adapter."""

    __slots__ = ("_service_proof",)

    def __init__(self, service_proof: object) -> None:
        self._service_proof = service_proof


def _finding_id(scan_handle: str, finding: Finding) -> str:
    raw = f"{scan_handle}\x00{finding.path}\x00{finding.artifact.value}".encode("utf-8")
    return "finding_" + hashlib.sha256(raw).hexdigest()[:32]


def _scan_summary(scan: SystemScan) -> dict[str, object]:
    report = system_to_dict(scan)
    return {
        "requested_roots": report["requested_roots"],
        "root_observations": report["root_observations"],
        "observation_failures": report["observation_failures"],
        "ambiguous_boundaries": report["ambiguous_boundaries"],
        "scan_metadata": report["scan_metadata"],
        "summary": report["summary"],
    }


def _finding_model(finding_id: str, finding: Finding) -> dict[str, object]:
    model = finding_to_dict(finding)
    model["finding_id"] = finding_id
    return model


def _plan_item_model(item: object) -> dict[str, object]:
    snapshot = item.snapshot
    return {
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
        "rule_trace": _json_value(snapshot.rule_trace),
    }


def _review_model(handle: str, state: McpHandleState, review: _ReviewState) -> dict[str, object]:
    return {
        "status": state.value,
        "review_handle": handle,
        "session_id": review.session.session_id,
        "plan_id": review.plan.plan_id.value,
        "engine_version": review.plan.engine_version,
        "approved_root": review.plan.approved_root.path,
        "items": [_plan_item_model(item) for item in review.plan.items],
        "exclusions": [
            {"artifact": item.artifact.value, "path": item.path, "reason": item.reason}
            for item in review.plan.exclusions
        ],
        "human_confirmation": "received" if review.confirmation is not None else "required",
    }


def _result_status(result: CleanupApplicationResult) -> str:
    if result.state is CleanupSessionState.PARTIAL:
        return "PARTIAL_RESULT"
    if result.state is CleanupSessionState.RECONCILIATION_REQUIRED:
        return McpHandleState.RECONCILIATION_REQUIRED.value
    if result.state is CleanupSessionState.EXECUTED:
        return "EXECUTED"
    if result.validation_status is not None and result.validation_status.value != "valid":
        return McpErrorCode.REVALIDATION_BLOCKED.value
    return "BLOCKED"


class McpService:
    """Service boundary used by MCP requests.

    The public methods that accept MCP-shaped arguments validate only handles,
    IDs, and read-only scan roots. Trusted human confirmation is intentionally
    available only through ``confirm_from_human_channel`` and a private token
    that is never reachable from the MCP tool registry.
    """

    def __init__(
        self,
        *,
        scan_fn: Callable[[SystemScanOptions], SystemScan] = scan_system,
        plan_fn: Callable[[SystemScan, tuple[Finding, ...]], object] = create_system_cleanup_plan,
        revalidator_factory: Callable[[], object] = system_engine_revalidator,
        runtime_factory: Callable[[], WorkspaceCleanupRuntime] = workspace_mutation_runtime,
        handle_ttl_seconds: float = 900.0,
        handle_capacity: int = OpaqueHandleStore.DEFAULT_MAX_ENTRIES,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._scan_fn = scan_fn
        self._plan_fn = plan_fn
        self._revalidator_factory = revalidator_factory
        self._runtime_factory = runtime_factory
        self._store = OpaqueHandleStore(
            ttl_seconds=handle_ttl_seconds,
            max_entries=handle_capacity,
            clock=clock,
        )
        self._human_proof = object()
        self._workflow_lock = threading.RLock()

    @property
    def tool_definitions(self) -> tuple[dict[str, object], ...]:
        return TOOL_DEFINITIONS

    def create_human_channel(self) -> _TrustedHumanChannel:
        """Create a trusted adapter token; never registered as an MCP tool."""

        return _TrustedHumanChannel(self._human_proof)

    def _scan_options(self, arguments: dict[str, Any], *, root: str | None = None) -> SystemScanOptions:
        roots = (root,) if root is not None else tuple(arguments.get("roots", ()))
        max_seconds = arguments.get("max_seconds", MCP_DEFAULT_MAX_SECONDS)
        max_nodes = arguments.get("max_nodes", MCP_DEFAULT_MAX_NODES)
        max_files = arguments.get("max_files", MCP_DEFAULT_MAX_FILES)
        validate_scan_budget(
            max_seconds=max_seconds,
            max_nodes=max_nodes,
            max_files=max_files,
        )
        limits = ScanLimits(
            max_seconds=max_seconds,
            max_nodes=max_nodes,
            max_files=max_files,
        )
        return SystemScanOptions(
            additional_roots=roots,
            include_fixed_drives=not bool(roots),
            include_user_profile=not bool(roots),
            include_global_storage=not bool(roots),
            allow_network=bool(arguments.get("allow_network", False)),
            limits=limits,
        )

    def _issue_scan(self, scan: SystemScan) -> dict[str, object]:
        findings: dict[str, Finding] = {}
        handle_placeholder = "scan_pending"
        for finding in scan.findings:
            findings[_finding_id(handle_placeholder, finding)] = finding
        handle = self._store.issue(McpHandleType.SCAN, _ScanState(scan, findings))
        remapped = {_finding_id(handle, finding): finding for finding in scan.findings}
        entry = self._store.resolve(handle, McpHandleType.SCAN)
        entry.payload = _ScanState(scan, remapped)
        return {
            "status": McpHandleState.ACTIVE.value,
            "scan_handle": handle,
            "summary": _scan_summary(scan),
            "findings_count": len(remapped),
        }

    def scan_system(self, arguments: dict[str, Any]) -> dict[str, object]:
        try:
            scan = self._scan_fn(self._scan_options(arguments))
        except McpServiceError:
            raise
        except (ValueError, OSError) as error:
            raise McpServiceError(McpErrorCode.INVALID_REQUEST, f"scan could not start: {error}") from error
        except Exception as error:
            raise McpServiceError(McpErrorCode.INTERNAL_ERROR, "scan failed at the engine boundary") from error
        if not isinstance(scan, SystemScan):
            raise McpServiceError(McpErrorCode.INTERNAL_ERROR, "engine returned an invalid scan result")
        return self._issue_scan(scan)

    def scan_root(self, arguments: dict[str, Any]) -> dict[str, object]:
        return self.scan_system({**arguments, "roots": [arguments["root"]]})

    def _scan_entry(self, handle: object):
        return self._store.resolve(handle, McpHandleType.SCAN)

    def get_scan_summary(self, arguments: dict[str, Any]) -> dict[str, object]:
        entry = self._scan_entry(arguments["scan_handle"])
        return {"status": entry.state.value, "scan_handle": entry.handle, "summary": _scan_summary(entry.payload.scan)}

    def list_findings(self, arguments: dict[str, Any]) -> dict[str, object]:
        entry = self._scan_entry(arguments["scan_handle"])
        return {
            "status": entry.state.value,
            "scan_handle": entry.handle,
            "findings": [_finding_model(finding_id, finding) for finding_id, finding in sorted(entry.payload.findings.items())],
        }

    def get_finding(self, arguments: dict[str, Any], *, explanation: bool = False) -> dict[str, object]:
        entry = self._scan_entry(arguments["scan_handle"])
        finding = entry.payload.findings.get(arguments["finding_id"])
        if finding is None:
            raise McpServiceError(McpErrorCode.INVALID_HANDLE, "finding ID is not bound to this scan handle")
        model = _finding_model(arguments["finding_id"], finding)
        if explanation:
            model["explanation"] = {
                "summary": finding.summary,
                "safety_decision": _json_value(finding.safety_decision),
                "rule_trace": _json_value(finding.rule_trace),
                "evidence": _json_value(finding.evidence),
            }
        return model

    def create_cleanup_review(self, arguments: dict[str, Any]) -> dict[str, object]:
        scan_entry = self._scan_entry(arguments["scan_handle"])
        finding_ids = tuple(arguments["finding_ids"])
        if len(set(finding_ids)) != len(finding_ids):
            raise McpServiceError(McpErrorCode.INVALID_REQUEST, "finding IDs must be unique")
        selected: list[Finding] = []
        for finding_id in finding_ids:
            finding = scan_entry.payload.findings.get(finding_id)
            if finding is None:
                raise McpServiceError(McpErrorCode.INVALID_HANDLE, "finding ID is not bound to this scan handle")
            selected.append(finding)
        try:
            plan = self._plan_fn(scan_entry.payload.scan, tuple(selected))
            if not getattr(plan, "items", ()):
                raise ValueError("engine produced no eligible cleanup items")
            session = create_cleanup_session(plan)
        except (TypeError, ValueError) as error:
            raise McpServiceError(McpErrorCode.REVALIDATION_BLOCKED, f"engine blocked cleanup planning: {error}") from error
        review = _ReviewState(scan_entry.handle, scan_entry.payload.scan, plan, session)
        handle = self._store.issue(
            McpHandleType.REVIEW,
            review,
            state=McpHandleState.WAITING_FOR_HUMAN_CONFIRMATION,
        )
        return _review_model(handle, McpHandleState.WAITING_FOR_HUMAN_CONFIRMATION, review)

    def _review_entry(self, handle: object, *, allow_consumed: bool = False):
        return self._store.resolve(handle, McpHandleType.REVIEW, allow_consumed=allow_consumed)

    def get_cleanup_review(self, arguments: dict[str, Any]) -> dict[str, object]:
        entry = self._review_entry(arguments["review_handle"])
        return _review_model(entry.handle, entry.state, entry.payload)

    def confirm_from_human_channel(
        self,
        review_handle: str,
        *,
        confirmation_phrase: str,
        confirmed_at: str | None = None,
        channel: _TrustedHumanChannel,
    ) -> dict[str, object]:
        if not isinstance(channel, _TrustedHumanChannel) or channel._service_proof is not self._human_proof:
            raise McpServiceError(McpErrorCode.HUMAN_CONFIRMATION_REQUIRED, "confirmation must come from the trusted human channel")
        if confirmation_phrase != CONFIRMATION_PHRASE:
            raise McpServiceError(McpErrorCode.HUMAN_CONFIRMATION_REQUIRED, "the exact human confirmation phrase was not supplied")
        with self._workflow_lock:
            entry = self._review_entry(review_handle)
            review = entry.payload
            if review.confirmation is None:
                try:
                    review.confirmation = create_human_confirmation(
                        review.session,
                        review.session.review,
                        confirmation_phrase=confirmation_phrase,
                        confirmed_at=confirmed_at or datetime.now(timezone.utc).isoformat(),
                    )
                except (TypeError, ValueError) as error:
                    raise McpServiceError(McpErrorCode.HUMAN_CONFIRMATION_REQUIRED, "trusted human confirmation was rejected") from error
                self._store.transition(review_handle, McpHandleType.REVIEW, McpHandleState.READY_FOR_EXECUTION)
            return _review_model(review_handle, McpHandleState.READY_FOR_EXECUTION, review)

    def request_cleanup_execution(self, arguments: dict[str, Any]) -> dict[str, object]:
        with self._workflow_lock:
            entry = self._review_entry(arguments["review_handle"])
            review: _ReviewState = entry.payload
            if review.confirmation is None:
                raise McpServiceError(McpErrorCode.HUMAN_CONFIRMATION_REQUIRED, "trusted human confirmation is required outside MCP")
            if review.execution_handle is not None:
                self._store.resolve(review.execution_handle, McpHandleType.EXECUTION, allow_consumed=True)
                if self._store.state(review.execution_handle, McpHandleType.EXECUTION, allow_consumed=True) is not McpHandleState.READY_FOR_EXECUTION:
                    raise McpServiceError(McpErrorCode.CONSUMED_HANDLE, "execution handle was already used")
                return {"status": McpHandleState.READY_FOR_EXECUTION.value, "execution_handle": review.execution_handle, "review_handle": entry.handle}
            execution = _ExecutionState(entry.handle, review)
            handle = self._store.issue(McpHandleType.EXECUTION, execution, state=McpHandleState.READY_FOR_EXECUTION)
            review.execution_handle = handle
            return {"status": McpHandleState.READY_FOR_EXECUTION.value, "execution_handle": handle, "review_handle": entry.handle}

    def _execution_entry(self, handle: object, *, allow_consumed: bool = False):
        return self._store.resolve(handle, McpHandleType.EXECUTION, allow_consumed=allow_consumed)

    def _safe_execution_result(self, execution_handle: str, execution: _ExecutionState) -> dict[str, object]:
        result = execution.result
        if result is None:
            return {"status": execution.status, "execution_handle": execution_handle, "error": execution.error}
        recovery_by_item: dict[str, str] = {}
        for recovery_handle in execution.recovery_handles:
            recovery_entry = self._store.resolve(recovery_handle, McpHandleType.RECOVERY, allow_consumed=True)
            recovery_by_item[recovery_entry.payload.recovery_id] = recovery_handle
        return {
            "status": _result_status(result),
            "execution_handle": execution_handle,
            "session_id": result.session_id,
            "plan_id": result.plan_id.value,
            "validation_status": result.validation_status.value if result.validation_status is not None else None,
            "authorization_status": result.authorization_status.value if result.authorization_status is not None else None,
            "transactional": False,
            "reason": result.reason,
            "item_results": [
                {
                    "plan_item_id": item.plan_item_id.value,
                    "outcome": item.outcome.value,
                    "quarantine_state": item.quarantine_state.value if item.quarantine_state is not None else None,
                    "recovery_handle": recovery_by_item.get(item.recovery_id or ""),
                    "recovery_id": item.recovery_id,
                    "reason": item.reason,
                }
                for item in result.item_results
            ],
        }

    def execute_cleanup(self, arguments: dict[str, Any]) -> dict[str, object]:
        handle = arguments["execution_handle"]
        execution: _ExecutionState = self._store.consume(handle, McpHandleType.EXECUTION)
        execution.status = McpHandleState.EXECUTING.value
        try:
            runtime = self._runtime_factory()
            result = execute_cleanup_session(
                execution.review.session,
                execution.review.confirmation,
                engine_revalidator=self._revalidator_factory(),
                mutation_provider=runtime.provider,
            )
            execution.runtime = runtime
            for item in result.item_results:
                if item.recovery_id:
                    execution.recovery_handles.append(self._store.issue(
                        McpHandleType.RECOVERY,
                        _RecoveryState(handle, runtime, item.recovery_id),
                    ))
            execution.result = result
            execution.status = _result_status(result)
            terminal = McpHandleState.RECONCILIATION_REQUIRED if result.state is CleanupSessionState.RECONCILIATION_REQUIRED else McpHandleState.COMPLETE
            self._store.complete(handle, McpHandleType.EXECUTION, terminal)
            return self._safe_execution_result(handle, execution)
        except Exception as error:
            execution.error = "execution failed at the engine boundary"
            execution.status = McpErrorCode.EXECUTION_FAILED.value
            self._store.complete(handle, McpHandleType.EXECUTION, McpHandleState.FAILED)
            raise McpServiceError(McpErrorCode.EXECUTION_FAILED, execution.error) from error

    def get_execution_status(self, arguments: dict[str, Any]) -> dict[str, object]:
        entry = self._execution_entry(arguments["execution_handle"], allow_consumed=True)
        return self._safe_execution_result(entry.handle, entry.payload)

    def _recovery_model(self, handle: str, state: _RecoveryState) -> dict[str, object]:
        entry = None
        if state.runtime is not None:
            reconciliation = state.runtime.recovery_entries()
            entries = getattr(reconciliation, "entries", reconciliation if isinstance(reconciliation, tuple) else ())
            entry = next((item for item in reversed(entries) if item.recovery_id == state.recovery_id), None)
        if entry is None and state.result is not None:
            entry = state.result.entry
        if entry is None:
            raise McpServiceError(McpErrorCode.RECOVERY_NOT_FOUND, "validated recovery entry was not found")
        status = entry.status.value
        eligible = status in {QuarantineState.QUARANTINED.value, QuarantineState.QUARANTINE_COMMITTED_UNJOURNALED.value}
        return {
            "status": status,
            "recovery_handle": handle,
            "recovery_id": state.recovery_id,
            "original_path": entry.original_path,
            "quarantine_path": entry.quarantine_path,
            "restore_eligible": eligible,
            "failure_reason": entry.failure_reason,
        }

    def get_recovery_status(self, arguments: dict[str, Any]) -> dict[str, object]:
        execution_entry = self._execution_entry(arguments["execution_handle"], allow_consumed=True)
        execution: _ExecutionState = execution_entry.payload
        return {
            "status": execution.status,
            "execution_handle": execution_entry.handle,
            "recoveries": [
                self._recovery_model(handle, self._store.resolve(handle, McpHandleType.RECOVERY, allow_consumed=True).payload)
                for handle in execution.recovery_handles
            ],
        }

    def request_undo(self, arguments: dict[str, Any]) -> dict[str, object]:
        handle = arguments["recovery_handle"]
        state: _RecoveryState = self._store.consume(handle, McpHandleType.RECOVERY)
        try:
            state.result = state.runtime.undo(state.recovery_id)
            self._store.complete(handle, McpHandleType.RECOVERY, McpHandleState.COMPLETE)
            return {
                "status": state.result.state.value.upper(),
                "recovery_handle": handle,
                "recovery_id": state.recovery_id,
                "failure_reason": state.result.failure_reason,
            }
        except Exception as error:
            self._store.complete(handle, McpHandleType.RECOVERY, McpHandleState.FAILED)
            raise McpServiceError(McpErrorCode.EXECUTION_FAILED, "restore failed at the engine boundary") from error

    def call_tool(self, name: str, arguments: object) -> dict[str, object]:
        validated = validate_arguments(name, arguments)
        handlers: dict[str, Callable[[dict[str, Any]], dict[str, object]]] = {
            "dwi_scan_system": self.scan_system,
            "dwi_scan_root": self.scan_root,
            "dwi_get_scan_summary": self.get_scan_summary,
            "dwi_list_findings": self.list_findings,
            "dwi_get_finding": self.get_finding,
            "dwi_explain_finding": lambda args: self.get_finding(args, explanation=True),
            "dwi_create_cleanup_review": self.create_cleanup_review,
            "dwi_get_cleanup_review": self.get_cleanup_review,
            "dwi_request_cleanup_execution": self.request_cleanup_execution,
            "dwi_execute_cleanup": self.execute_cleanup,
            "dwi_get_execution_status": self.get_execution_status,
            "dwi_get_recovery_status": self.get_recovery_status,
            "dwi_request_undo": self.request_undo,
        }
        handler = handlers.get(name)
        if handler is None:
            raise McpServiceError(McpErrorCode.INVALID_REQUEST, f"unknown MCP tool: {name}")
        return handler(validated)
