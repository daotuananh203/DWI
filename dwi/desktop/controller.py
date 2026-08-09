"""Testable Desktop state model and orchestration controller."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Callable, Iterable

from ..application import (
    CleanupApplicationResult,
    CleanupMutationProvider,
    CleanupSession,
    CleanupSessionState,
    create_cleanup_session,
    create_human_confirmation,
    execute_cleanup_session,
)
from ..cleanup import CleanupPlan, QuarantineState
from ..cleanup_engine import (
    WorkspaceCleanupRuntime,
    create_system_cleanup_plan,
    system_engine_revalidator,
    workspace_mutation_runtime,
)
from ..domain import ActionEligibility
from ..pipeline import Finding as PipelineFinding
from ..scan_control import ScanLimits, ScanTermination
from ..system_scan import RootStatus, SystemScan, SystemScanOptions, scan_system
from .i18n import DesktopSettings, Translator
from .worker import CancelResult, CancellationToken, DesktopWorker, WorkCancelled, WorkPhase, WorkerBusyError


CONFIRMATION_PHRASE = "I reviewed this exact cleanup plan."


class DesktopState(str, Enum):
    IDLE = "idle"
    SCANNING = "scanning"
    SCAN_COMPLETE = "scan_complete"
    SCAN_PARTIAL = "scan_partial"
    SCAN_FAILED = "scan_failed"
    REVIEWING = "reviewing"
    CONFIRMING = "confirming"
    REVALIDATING = "revalidating"
    EXECUTING = "executing"
    PARTIAL_RESULT = "partial_result"
    CLEANUP_COMPLETE = "cleanup_complete"
    RECONCILIATION_REQUIRED = "reconciliation_required"
    RECOVERY = "recovery"
    CANCELLED = "cancelled"
    ERROR = "error"


@dataclass(frozen=True)
class FindingRow:
    key: str
    path: str
    artifact: str
    provenance: str
    known_bytes: int
    size_complete: bool
    risk_label: str
    action_eligibility: str
    regenerability: str
    reachability: str
    activity: str
    protection: str
    reclaim_priority: str
    executable: bool


@dataclass(frozen=True)
class ReviewModel:
    session_id: str
    plan_id: str
    engine_version: str
    items: tuple[FindingRow, ...]
    known_total_bytes: int
    partial_size_count: int
    exclusions: tuple[str, ...]
    plan_digest: str
    review_digest: str


@dataclass(frozen=True)
class RecoveryRow:
    recovery_id: str
    original_path: str
    quarantine_path: str | None
    state: str
    restore_eligible: bool
    warning: str | None = None


@dataclass
class DesktopStateModel:
    state: DesktopState = DesktopState.IDLE
    scan: SystemScan | None = None
    selected_finding_keys: tuple[str, ...] = ()
    plan: CleanupPlan | None = None
    session: CleanupSession | None = None
    review: ReviewModel | None = None
    confirmation: object | None = None
    result: CleanupApplicationResult | None = None
    recovery_rows: tuple[RecoveryRow, ...] = ()
    status_message: str = ""
    error_message: str | None = None
    progress_indeterminate: bool = False
    operation_name: str | None = None
    operation_phase: WorkPhase = WorkPhase.IDLE
    settings: DesktopSettings = field(default_factory=DesktopSettings)


@dataclass(frozen=True)
class _ExecutionEnvelope:
    confirmation: object
    result: CleanupApplicationResult
    recovery_rows: tuple[RecoveryRow, ...]
    recovery_error: str | None = None


def finding_key(finding: PipelineFinding) -> str:
    return f"{finding.artifact.value}::{finding.path.casefold()}"


def _format_provenance(finding: PipelineFinding) -> str:
    provenance = finding.interpretation.provenance
    return f"{provenance.ecosystem}/{provenance.generator}"


def finding_to_row(finding: PipelineFinding) -> FindingRow:
    interpretation = finding.interpretation
    priority = interpretation.reclaim_priority.value if interpretation.reclaim_priority else "unknown"
    return FindingRow(
        finding_key(finding),
        finding.path,
        finding.artifact.value,
        _format_provenance(finding),
        finding.size.known_bytes,
        finding.size.complete,
        finding.risk_label.value,
        finding.action_eligibility.value,
        interpretation.regenerability.value,
        interpretation.reachability.value,
        interpretation.activity.value,
        interpretation.protection.value,
        priority,
        finding.action_eligibility is ActionEligibility.ELIGIBLE_FOR_EXPLICIT_ACTION
        and finding.risk_label.value in {"safe", "regeneratable"},
    )


def _latest_recovery_rows(entries: Iterable[object]) -> tuple[RecoveryRow, ...]:
    latest: dict[str, object] = {}
    for entry in entries:
        recovery_id = getattr(entry, "recovery_id", "")
        if recovery_id:
            latest[recovery_id] = entry
    rows: list[RecoveryRow] = []
    for recovery_id, entry in sorted(latest.items()):
        status = getattr(getattr(entry, "status", None), "value", "unknown")
        eligible = status in {
            QuarantineState.QUARANTINED.value,
            QuarantineState.QUARANTINE_COMMITTED_UNJOURNALED.value,
        }
        rows.append(RecoveryRow(
            recovery_id,
            getattr(entry, "original_path", ""),
            getattr(entry, "quarantine_path", None),
            status,
            eligible,
            getattr(entry, "failure_reason", None),
        ))
    return tuple(rows)


class DesktopController:
    """Presentation/orchestration only; safety decisions remain engine-owned."""

    def __init__(
        self,
        *,
        dispatch: Callable[[Callable[[], None]], None] | None = None,
        worker: DesktopWorker | None = None,
        scan_fn: Callable[[SystemScanOptions], SystemScan] = scan_system,
        plan_fn: Callable[[SystemScan, tuple[PipelineFinding, ...]], CleanupPlan] = create_system_cleanup_plan,
        revalidator_factory: Callable[[], object] = system_engine_revalidator,
        runtime_factory: Callable[[], WorkspaceCleanupRuntime] = workspace_mutation_runtime,
        translator: Translator | None = None,
    ) -> None:
        self.state = DesktopStateModel()
        self.translator = translator or Translator()
        self._dispatch = dispatch or (lambda callback: callback())
        self.worker = worker or DesktopWorker(self._dispatch)
        self._owns_worker = worker is None
        self._scan_fn = scan_fn
        self._plan_fn = plan_fn
        self._revalidator_factory = revalidator_factory
        self._runtime_factory = runtime_factory
        self._runtime: WorkspaceCleanupRuntime | None = None
        self._listeners: list[Callable[[DesktopStateModel], None]] = []
        self._findings: dict[str, PipelineFinding] = {}
        self._filters: dict[str, str] = {"search": "", "risk": "all", "eligibility": "all", "artifact": "all", "provenance": "all"}
        self._sort = "path"

    def subscribe(self, listener: Callable[[DesktopStateModel], None]) -> None:
        self._listeners.append(listener)

    def close(self) -> bool:
        if self.busy:
            return False
        if self._owns_worker:
            return self.worker.close(wait=True)
        return True

    def _emit(self) -> None:
        for listener in tuple(self._listeners):
            listener(self.state)

    def _update(self, **changes: object) -> None:
        for name, value in changes.items():
            setattr(self.state, name, value)
        self._emit()

    @property
    def busy(self) -> bool:
        return self.worker.busy

    @property
    def operation_phase(self) -> WorkPhase:
        return self.state.operation_phase

    @property
    def can_cancel(self) -> bool:
        if self.state.state in {DesktopState.REVIEWING, DesktopState.CONFIRMING} and not self.busy:
            return True
        return self.worker.cancellable

    def _phase_changed(self, phase: WorkPhase) -> None:
        changes: dict[str, object] = {"operation_phase": phase}
        if phase is WorkPhase.AUTHORIZED_MUTATION:
            changes["state"] = DesktopState.RECOVERY if self.state.operation_name == "undo" else DesktopState.EXECUTING
        if phase is WorkPhase.FINALIZING:
            message_key = "status.finishing_restore" if self.state.operation_name == "undo" else "status.finishing_cleanup"
        elif phase is WorkPhase.AUTHORIZED_MUTATION:
            message_key = "status.restore_non_interruptible" if self.state.operation_name == "undo" else "status.cleanup_non_interruptible"
        elif phase is WorkPhase.RECONCILING:
            message_key = "status.finishing_restore" if self.state.operation_name == "undo" else "status.finishing_cleanup"
        elif phase is WorkPhase.CANCELLED:
            message_key = "status.cancelled"
        else:
            return self._update(**changes)
        changes["status_message"] = self.translator(message_key)
        self._update(**changes)

    def set_locale(self, locale: str) -> None:
        self.translator.set_locale(locale)
        self._update(settings=self.state.settings.with_locale(self.translator.locale))

    def set_scan_limits(self, *, max_seconds: float | None, max_nodes: int | None, max_files: int | None) -> None:
        self._update(settings=DesktopSettings(
            locale=self.translator.locale,
            max_seconds=max_seconds,
            max_nodes=max_nodes,
            max_files=max_files,
            allow_network=self.state.settings.allow_network,
        ))

    def set_allow_network(self, enabled: bool) -> None:
        self._update(settings=DesktopSettings(
            locale=self.translator.locale,
            max_seconds=self.state.settings.max_seconds,
            max_nodes=self.state.settings.max_nodes,
            max_files=self.state.settings.max_files,
            allow_network=bool(enabled),
        ))

    def start_system_scan(self, root: str | None = None) -> bool:
        if self.busy:
            return False
        if root:
            options = SystemScanOptions(
                additional_roots=(root,),
                include_fixed_drives=False,
                include_user_profile=False,
                include_global_storage=False,
                allow_network=self.state.settings.allow_network,
                limits=ScanLimits(
                    self.state.settings.max_seconds,
                    self.state.settings.max_nodes,
                    self.state.settings.max_files,
                ),
            )
        else:
            options = SystemScanOptions(
                allow_network=self.state.settings.allow_network,
                limits=ScanLimits(
                    self.state.settings.max_seconds,
                    self.state.settings.max_nodes,
                    self.state.settings.max_files,
                ),
            )
        self._update(
            state=DesktopState.SCANNING,
            status_message=self.translator("status.scanning"),
            error_message=None,
            progress_indeterminate=True,
            operation_name="scan",
            operation_phase=WorkPhase.CANCELLABLE,
            selected_finding_keys=(),
            plan=None,
            session=None,
            review=None,
            result=None,
        )
        try:
            self.worker.submit(
                lambda cancellation: self._scan_fn(
                    SystemScanOptions(
                        additional_roots=options.additional_roots,
                        drive=options.drive,
                        include_fixed_drives=options.include_fixed_drives,
                        include_user_profile=options.include_user_profile,
                        include_global_storage=options.include_global_storage,
                        global_storage_roots=options.global_storage_roots,
                        allow_network=options.allow_network,
                        limits=options.limits,
                        cancellation=cancellation.is_set,
                    )
                ),
                on_success=self._scan_succeeded,
                on_error=self._scan_failed,
                on_cancel=lambda: self._update(state=DesktopState.CANCELLED, status_message=self.translator("status.cancelled"), progress_indeterminate=False, operation_name=None),
                on_phase=self._phase_changed,
            )
        except WorkerBusyError:
            return False
        return True

    def cancel(self) -> CancelResult:
        if not self.busy and self.state.state in {DesktopState.REVIEWING, DesktopState.CONFIRMING}:
            self._update(
                state=DesktopState.CANCELLED,
                operation_phase=WorkPhase.CANCELLED,
                status_message=self.translator("status.cancelled"),
                progress_indeterminate=False,
                operation_name=None,
            )
            return CancelResult.ACCEPTED
        result = self.worker.cancel()
        if result is CancelResult.ACCEPTED:
            self._update(status_message=self.translator("status.cancelling"))
        elif result is CancelResult.REJECTED_NON_CANCELLABLE:
            key = "status.restore_non_interruptible" if self.state.operation_name == "undo" else "status.cleanup_non_interruptible"
            self._update(status_message=self.translator(key))
        return result

    def request_close(self) -> CancelResult:
        """Request safe cancellation or report that the terminal phase must finish."""

        result = self.cancel()
        if self.busy:
            self._update(status_message=self.translator("status.please_wait_close"))
        return result

    def _scan_succeeded(self, scan: SystemScan) -> None:
        self._findings = {finding_key(finding): finding for finding in scan.findings}
        partial = (
            scan.termination is not ScanTermination.COMPLETED
            or bool(scan.observation_failures)
            or bool(scan.ambiguous_boundaries)
            or any(item.status is not RootStatus.COMPLETE for item in scan.root_observations)
        )
        cancelled = scan.termination is ScanTermination.CANCELLED
        self._update(
            state=DesktopState.CANCELLED if cancelled else DesktopState.SCAN_PARTIAL if partial else DesktopState.SCAN_COMPLETE,
            scan=scan,
            status_message=self.translator("status.cancelled" if cancelled else "state.scan_partial" if partial else "state.scan_complete"),
            error_message=None,
            progress_indeterminate=False,
            operation_name=None,
        )

    def _scan_failed(self, error: Exception) -> None:
        self._update(
            state=DesktopState.SCAN_FAILED,
            status_message=self.translator("state.scan_failed"),
            error_message=str(error),
            progress_indeterminate=False,
            operation_name=None,
        )

    def set_filter(self, name: str, value: str) -> None:
        if name in self._filters:
            self._filters[name] = value
        self._emit()

    def set_sort(self, value: str) -> None:
        if value in {"path", "size", "priority"}:
            self._sort = value
        self._emit()

    def filtered_findings(self) -> tuple[PipelineFinding, ...]:
        values = tuple(self._findings.values())
        search = self._filters["search"].casefold().strip()
        risk = self._filters["risk"]
        eligibility = self._filters["eligibility"]
        artifact = self._filters["artifact"]
        provenance = self._filters["provenance"]
        values = tuple(
            finding for finding in values
            if (not search or search in finding.path.casefold())
            and (risk == "all" or finding.risk_label.value == risk)
            and (
                eligibility == "all"
                or (eligibility in {"executable", ActionEligibility.ELIGIBLE_FOR_EXPLICIT_ACTION.value} and finding.action_eligibility is ActionEligibility.ELIGIBLE_FOR_EXPLICIT_ACTION and finding.risk_label.value in {"safe", "regeneratable"})
                or (eligibility == "review_only" and not (finding.action_eligibility is ActionEligibility.ELIGIBLE_FOR_EXPLICIT_ACTION and finding.risk_label.value in {"safe", "regeneratable"}))
            )
            and (artifact == "all" or finding.artifact.value == artifact)
            and (provenance == "all" or _format_provenance(finding) == provenance)
        )
        if self._sort == "size":
            values = tuple(sorted(values, key=lambda finding: (-finding.size.known_bytes, finding.path.casefold())))
        elif self._sort == "priority":
            values = tuple(sorted(values, key=lambda finding: (finding.interpretation.reclaim_priority.value, finding.path.casefold())))
        else:
            values = tuple(sorted(values, key=lambda finding: (finding.path.casefold(), finding.path)))
        return values

    def finding_rows(self) -> tuple[FindingRow, ...]:
        return tuple(finding_to_row(finding) for finding in self.filtered_findings())

    def finding_details(self, key: str) -> PipelineFinding | None:
        return self._findings.get(key)

    def toggle_selection(self, key: str) -> bool:
        finding = self._findings.get(key)
        if finding is None or finding.action_eligibility is not ActionEligibility.ELIGIBLE_FOR_EXPLICIT_ACTION or finding.risk_label.value not in {"safe", "regeneratable"}:
            return False
        selected = list(self.state.selected_finding_keys)
        if key in selected:
            selected.remove(key)
        else:
            selected.append(key)
        self._update(selected_finding_keys=tuple(sorted(selected)))
        return True

    def clear_selection(self) -> None:
        self._update(selected_finding_keys=())

    def build_cleanup_review(self) -> bool:
        if self.busy or self.state.scan is None or self.state.state not in {DesktopState.SCAN_COMPLETE}:
            self._update(error_message=self.translator("error.no_scan" if self.state.scan is None else "error.no_selection"))
            return False
        selected = tuple(self._findings[key] for key in self.state.selected_finding_keys if key in self._findings)
        if not selected:
            self._update(error_message=self.translator("error.no_selection"))
            return False
        self._update(state=DesktopState.REVIEWING, status_message=self.translator("status.reviewing"), error_message=None, progress_indeterminate=True, operation_name="review", operation_phase=WorkPhase.CANCELLABLE)
        try:
            self.worker.submit(
                lambda cancellation: (cancellation.checkpoint(), self._plan_fn(self.state.scan, selected))[1],
                on_success=self._review_succeeded,
                on_error=self._review_failed,
                on_cancel=lambda: self._update(state=DesktopState.CANCELLED, status_message=self.translator("status.cancelled"), progress_indeterminate=False, operation_name=None),
                on_phase=self._phase_changed,
            )
        except WorkerBusyError:
            return False
        return True

    def _review_succeeded(self, plan: CleanupPlan) -> None:
        if not plan.items:
            self._update(state=DesktopState.ERROR, status_message=self.translator("state.error"), error_message="engine produced no executable plan items", progress_indeterminate=False, operation_name=None, plan=plan)
            return
        session = create_cleanup_session(plan)
        items = tuple(finding_to_row(self._findings[key]) for key in self.state.selected_finding_keys if key in self._findings)
        self._update(
            state=DesktopState.REVIEWING,
            plan=plan,
            session=session,
            review=ReviewModel(
                session.session_id,
                plan.plan_id.value,
                plan.engine_version,
                items,
                sum(item.snapshot.size.known_bytes for item in plan.items),
                sum(not item.snapshot.size.complete for item in plan.items),
                tuple(f"{item.path}: {reason}" for item, reason in ((exclusion, exclusion.reason) for exclusion in plan.exclusions)),
                session.review.plan_digest,
                session.review.review_digest,
            ),
            status_message=self.translator("state.reviewing"),
            error_message=None,
            progress_indeterminate=False,
            operation_name=None,
            operation_phase=WorkPhase.IDLE,
        )

    def _review_failed(self, error: Exception) -> None:
        self._update(state=DesktopState.ERROR, status_message=self.translator("state.error"), error_message=str(error), progress_indeterminate=False, operation_name=None)

    def confirm_cleanup(self, phrase: str, *, confirmed_at: str | None = None) -> bool:
        if self.busy or self.state.session is None or self.state.review is None:
            self._update(error_message=self.translator("error.no_selection"))
            return False
        if phrase != CONFIRMATION_PHRASE:
            self._update(state=DesktopState.CONFIRMING, error_message=self.translator("review.phrase"))
            return False
        session = self.state.session
        review = session.review
        timestamp = confirmed_at or datetime.now(timezone.utc).isoformat()
        self._update(state=DesktopState.CONFIRMING, status_message=self.translator("state.confirming"), error_message=None, progress_indeterminate=True, operation_name="cleanup", operation_phase=WorkPhase.CANCELLABLE)
        try:
            self.worker.submit(
                lambda cancellation: self._execute(session, review, phrase, timestamp, cancellation),
                on_started=lambda: self._update(state=DesktopState.REVALIDATING, status_message=self.translator("status.revalidating")),
                on_success=self._cleanup_succeeded,
                on_error=self._cleanup_failed,
                on_cancel=lambda: self._update(state=DesktopState.CANCELLED, status_message=self.translator("status.cancelled"), progress_indeterminate=False, operation_name=None),
                on_phase=self._phase_changed,
            )
        except WorkerBusyError:
            return False
        return True

    def _execute(self, session: CleanupSession, review: object, phrase: str, timestamp: str, cancellation: CancellationToken) -> _ExecutionEnvelope:
        cancellation.checkpoint()
        confirmation = create_human_confirmation(session, review, confirmation_phrase=phrase, confirmed_at=timestamp)
        cancellation.enter_phase(WorkPhase.FINALIZING)
        self._dispatch(lambda: self._update(state=DesktopState.REVALIDATING, status_message=self.translator("status.finishing_cleanup")))
        runtime = self._runtime or self._new_runtime()
        provider = CleanupMutationProvider(
            lambda plan: self._phase_recovery_context(runtime.provider, cancellation, plan),
            lambda plan, validation, authorization: self._phase_authorized_context(
                runtime.provider, cancellation, plan, validation, authorization,
            ),
        )
        result = execute_cleanup_session(
            session,
            confirmation,
            engine_revalidator=self._revalidator_factory(),
            mutation_provider=provider,
        )
        rows: tuple[RecoveryRow, ...] = ()
        recovery_error: str | None = None
        if runtime is not None:
            try:
                cancellation.enter_phase(WorkPhase.RECONCILING)
                reconciliation = runtime.recovery_entries()
                rows = _latest_recovery_rows(reconciliation.entries)
                if reconciliation.failures:
                    recovery_error = "; ".join(reconciliation.failures)
            except Exception as error:
                recovery_error = str(error)
        cancellation.terminal(WorkPhase.COMPLETE)
        return _ExecutionEnvelope(confirmation, result, rows, recovery_error)

    @staticmethod
    def _phase_recovery_context(provider: CleanupMutationProvider, token: CancellationToken, plan: CleanupPlan):
        token.enter_phase(WorkPhase.RECONCILING)
        return provider.recovery_context(plan)

    @staticmethod
    def _phase_authorized_context(provider: CleanupMutationProvider, token: CancellationToken, plan: CleanupPlan, validation: object, authorization: object):
        token.enter_phase(WorkPhase.AUTHORIZED_MUTATION)
        return provider.authorized_context(plan, validation, authorization)

    def _new_runtime(self) -> WorkspaceCleanupRuntime:
        self._runtime = self._runtime_factory()
        return self._runtime

    def _cleanup_succeeded(self, envelope: _ExecutionEnvelope) -> None:
        result = envelope.result
        if envelope.recovery_error:
            state = DesktopState.RECONCILIATION_REQUIRED
            message = self.translator("status.reconciliation")
        elif result.state is CleanupSessionState.EXECUTED:
            state = DesktopState.CLEANUP_COMPLETE
            message = self.translator("status.done")
        elif result.state is CleanupSessionState.PARTIAL:
            state = DesktopState.PARTIAL_RESULT
            message = self.translator("status.done")
        elif result.state is CleanupSessionState.RECONCILIATION_REQUIRED:
            state = DesktopState.RECONCILIATION_REQUIRED
            message = self.translator("status.reconciliation")
        else:
            state = DesktopState.ERROR
            message = result.reason or self.translator("state.error")
        self._update(state=state, confirmation=envelope.confirmation, result=result, recovery_rows=envelope.recovery_rows, status_message=message, error_message=result.reason, progress_indeterminate=False, operation_name=None, operation_phase=WorkPhase.COMPLETE)

    def _cleanup_failed(self, error: Exception) -> None:
        self._update(state=DesktopState.ERROR, status_message=self.translator("state.error"), error_message=str(error), progress_indeterminate=False, operation_name=None, operation_phase=WorkPhase.FAILED)

    def refresh_recovery(self) -> bool:
        if self._runtime is None:
            self._update(state=DesktopState.RECOVERY, recovery_rows=(), status_message=self.translator("state.recovery"), error_message=None)
            return True
        if self.busy:
            return False
        self._update(state=DesktopState.RECOVERY, status_message=self.translator("state.recovery"), progress_indeterminate=True, operation_name="recovery", operation_phase=WorkPhase.CANCELLABLE)
        try:
            self.worker.submit(
                lambda cancellation: (cancellation.checkpoint(), self._runtime.recovery_entries())[1],
                on_success=self._recovery_succeeded,
                on_error=lambda error: self._update(state=DesktopState.RECONCILIATION_REQUIRED, recovery_rows=(), progress_indeterminate=False, operation_name=None, error_message=str(error)),
                on_cancel=lambda: self._update(state=DesktopState.CANCELLED, status_message=self.translator("status.cancelled"), progress_indeterminate=False, operation_name=None, operation_phase=WorkPhase.CANCELLED),
                on_phase=self._phase_changed,
            )
        except WorkerBusyError:
            return False
        return True

    def _recovery_succeeded(self, reconciliation: object) -> None:
        failures = tuple(getattr(reconciliation, "failures", ()))
        self._update(
            state=DesktopState.RECONCILIATION_REQUIRED if failures else DesktopState.RECOVERY,
            recovery_rows=_latest_recovery_rows(getattr(reconciliation, "entries", ())),
            progress_indeterminate=False,
            operation_name=None,
            error_message="; ".join(failures) if failures else None,
        )

    def undo(self, recovery_id: str) -> bool:
        if self.busy or self._runtime is None:
            return False
        allowed = {row.recovery_id for row in self.state.recovery_rows if row.restore_eligible}
        if recovery_id not in allowed:
            self._update(state=DesktopState.RECONCILIATION_REQUIRED, error_message=self.translator("error.reconciliation"))
            return False
        self._update(state=DesktopState.RECOVERY, progress_indeterminate=True, operation_name="undo", error_message=None, operation_phase=WorkPhase.CANCELLABLE)
        try:
            self.worker.submit(
                lambda cancellation: self._undo_operation(self._runtime, recovery_id, cancellation),
                on_success=lambda result: self._undo_succeeded(result),
                on_error=lambda error: self._update(state=DesktopState.RECONCILIATION_REQUIRED, progress_indeterminate=False, operation_name=None, error_message=str(error)),
                on_cancel=lambda: self._update(state=DesktopState.CANCELLED, status_message=self.translator("status.cancelled"), progress_indeterminate=False, operation_name=None, operation_phase=WorkPhase.CANCELLED),
                on_phase=self._phase_changed,
            )
        except WorkerBusyError:
            return False
        return True

    def _undo_succeeded(self, result: object) -> None:
        status = getattr(getattr(result, "state", None), "value", "failed")
        self._update(state=DesktopState.RECOVERY if status in {QuarantineState.RESTORED.value, QuarantineState.RESTORE_COMMITTED_UNJOURNALED.value} else DesktopState.RECONCILIATION_REQUIRED, status_message=self.translator("status.done"), progress_indeterminate=False, operation_name=None, error_message=getattr(result, "failure_reason", None), operation_phase=WorkPhase.COMPLETE)
        self.refresh_recovery()

    @staticmethod
    def _undo_operation(runtime: WorkspaceCleanupRuntime, recovery_id: str, token: CancellationToken):
        token.checkpoint()
        return runtime.undo(
            recovery_id,
            phase_callback=lambda phase: token.enter_phase(WorkPhase(phase)),
            cancellation_checkpoint=token.checkpoint,
        )
