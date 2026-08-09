"""Internal, presentation-neutral human-confirmed cleanup orchestration.

This layer accepts only an engine-generated ``CleanupSession`` and opaque
mutation capabilities. It does not accept raw paths, create policy decisions,
or expose a public interface. Human confirmation is a binding over the exact
reviewed immutable plan; execution always performs fresh validation afterward.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Mapping

from .cleanup import (
    CleanupPlan,
    ExecutionAuthorizationStatus,
    FindingSnapshot,
    PlanId,
    PlanItemId,
    PlanValidation,
    PlanValidationStatus,
    QuarantineState,
    TrustedScanContext,
    _digest,
    authorize_execution,
    validate_cleanup_plan,
)
from .mutation import (
    AuditJournal,
    MutationRoot,
    QuarantineRoot,
    QuarantineResult,
    ReconciliationResult,
    reconcile_pending_operations,
    quarantine_plan,
)


_APPLICATION_CAPABILITY = object()
_REVIEW_VERSION = "dwi-cleanup-review-v0.3"


class CleanupSessionState(str, Enum):
    REVIEW_READY = "review_ready"
    BLOCKED = "blocked"
    RECONCILIATION_REQUIRED = "reconciliation_required"
    EXECUTED = "executed"
    PARTIAL = "partial"
    REPLAYED = "replayed"


class CleanupItemOutcome(str, Enum):
    SUCCEEDED = "succeeded"
    RECOVERABLE = "recoverable"
    FAILED = "failed"
    BLOCKED = "blocked"
    REPLAYED = "replayed"


@dataclass(frozen=True)
class TrustedSnapshotSet:
    """Opaque engine-produced current analysis for one exact cleanup plan."""

    plan_id: PlanId
    plan_digest: str
    plan_item_ids: tuple[PlanItemId, ...]
    engine_version: str
    scan_provenance: str
    snapshot_digest: str
    evaluation_identity: str
    created_at: str
    snapshots: tuple[tuple[PlanItemId, FindingSnapshot], ...]
    scan_context: TrustedScanContext
    _proof: object | None = field(default=None, repr=False, compare=False)

    @property
    def is_engine_bound(self) -> bool:
        return (
            self._proof is _APPLICATION_CAPABILITY
            and bool(self.plan_digest.strip())
            and self.plan_item_ids == tuple(item_id for item_id, _ in self.snapshots)
            and self.snapshot_digest == _digest(self.snapshots)
            and bool(self.engine_version.strip())
            and bool(self.scan_provenance.strip())
            and bool(self.evaluation_identity.strip())
            and bool(self.created_at.strip())
            and self.scan_context.is_engine_trusted
            and self.scan_context.scan_provenance == self.scan_provenance
            and self.evaluation_identity == _digest((
                self.plan_id,
                self.engine_version,
                self.scan_context,
                self.snapshots,
                self.created_at,
            ))
        )

    def is_bound_to(self, plan: CleanupPlan) -> bool:
        return (
            self.is_engine_bound
            and self.plan_id == plan.plan_id
            and self.plan_digest == _plan_digest(plan)
            and self.plan_item_ids == _plan_item_ids(plan)
            and tuple(item_id for item_id, _ in self.snapshots) == _plan_item_ids(plan)
        )

    def as_mapping(self, plan: CleanupPlan) -> Mapping[PlanItemId, FindingSnapshot]:
        if not self.is_bound_to(plan):
            raise ValueError("trusted snapshots are not bound to this cleanup plan")
        return dict(self.snapshots)


@dataclass(frozen=True)
class EngineRevalidator:
    """Internal capability for requesting fresh engine analysis after review."""

    _callback: Callable[[CleanupPlan], TrustedSnapshotSet] = field(repr=False, compare=False)
    _proof: object | None = field(default=None, repr=False, compare=False)

    def revalidate(self, plan: CleanupPlan) -> TrustedSnapshotSet:
        if self._proof is not _APPLICATION_CAPABILITY or not isinstance(plan, CleanupPlan):
            raise TypeError("fresh revalidation requires an engine revalidator")
        result = self._callback(plan)
        if not isinstance(result, TrustedSnapshotSet) or not result.is_bound_to(plan):
            raise ValueError("engine revalidator returned untrusted or mismatched snapshots")
        return result


@dataclass(frozen=True)
class CleanupReview:
    """Immutable review snapshot derived from exactly one cleanup plan."""

    plan_id: PlanId
    plan_digest: str
    reviewed_item_ids: tuple[PlanItemId, ...]
    review_digest: str
    review_token: str
    _proof: object | None = field(default=None, repr=False, compare=False)

    @property
    def is_engine_bound(self) -> bool:
        return (
            self._proof is _APPLICATION_CAPABILITY
            and self.review_digest == _review_digest(
                self.plan_id,
                self.plan_digest,
                self.reviewed_item_ids,
            )
        )


@dataclass(frozen=True)
class CleanupSession:
    """Engine-owned review session; it is not execution permission."""

    session_id: str
    plan: CleanupPlan
    review: CleanupReview
    state: CleanupSessionState = CleanupSessionState.REVIEW_READY
    _proof: object | None = field(default=None, repr=False, compare=False)

    @property
    def is_engine_bound(self) -> bool:
        return (
            self._proof is _APPLICATION_CAPABILITY
            and self.session_id == _session_id(self.plan, self.review)
            and self.review.is_engine_bound
            and self.review.plan_id == self.plan.plan_id
            and self.review.plan_digest == _plan_digest(self.plan)
            and self.review.reviewed_item_ids == _plan_item_ids(self.plan)
        )


@dataclass(frozen=True)
class HumanConfirmation:
    """Explicit confirmation bound to one exact session and reviewed plan."""

    session_id: str
    plan_id: PlanId
    plan_digest: str
    review_digest: str
    reviewed_item_ids: tuple[PlanItemId, ...]
    confirmation_phrase: str
    confirmed_at: str
    confirmation_token: str
    _proof: object | None = field(default=None, repr=False, compare=False)

    @property
    def is_engine_bound(self) -> bool:
        return self._proof is _APPLICATION_CAPABILITY and bool(self.confirmation_phrase.strip())


@dataclass(frozen=True)
class CleanupItemResult:
    plan_item_id: PlanItemId
    outcome: CleanupItemOutcome
    quarantine_state: QuarantineState | None
    recovery_id: str | None
    reason: str | None = None


@dataclass(frozen=True)
class CleanupApplicationResult:
    session_id: str
    plan_id: PlanId
    state: CleanupSessionState
    validation_status: PlanValidationStatus | None
    authorization_status: ExecutionAuthorizationStatus | None
    item_results: tuple[CleanupItemResult, ...]
    reconciliation: ReconciliationResult | None
    reason: str | None = None
    transactional: bool = False


def _plan_digest(plan: CleanupPlan) -> str:
    return _digest(plan)


def _plan_item_ids(plan: CleanupPlan) -> tuple[PlanItemId, ...]:
    return tuple(item.plan_item_id for item in plan.items)


def _review_digest(
    plan_id: PlanId,
    plan_digest: str,
    item_ids: tuple[PlanItemId, ...],
) -> str:
    return _digest((_REVIEW_VERSION, plan_id, plan_digest, item_ids))


def _session_id(plan: CleanupPlan, review: CleanupReview) -> str:
    return f"session-{_digest((plan.plan_id, review.review_digest))[:32]}"


def _trusted_snapshot_set(
    plan: CleanupPlan,
    snapshots: Mapping[PlanItemId, FindingSnapshot],
    scan_context: TrustedScanContext,
    *,
    engine_version: str,
    created_at: str,
) -> TrustedSnapshotSet:
    """Internal engine constructor used by the trusted revalidation path."""

    expected_item_ids = _plan_item_ids(plan)
    if set(snapshots) != set(expected_item_ids):
        raise ValueError("fresh engine snapshots must cover the exact plan items")
    ordered = tuple((item_id, snapshots[item_id]) for item_id in expected_item_ids)
    if not isinstance(scan_context, TrustedScanContext) or not scan_context.is_engine_trusted:
        raise ValueError("fresh engine snapshots require trusted scan context")
    return TrustedSnapshotSet(
        plan.plan_id,
        _plan_digest(plan),
        _plan_item_ids(plan),
        engine_version,
        scan_context.scan_provenance,
        _digest(ordered),
        _digest((plan.plan_id, engine_version, scan_context, ordered, created_at)),
        created_at,
        ordered,
        scan_context,
        _APPLICATION_CAPABILITY,
    )


def _engine_revalidator(callback: Callable[[CleanupPlan], TrustedSnapshotSet]) -> EngineRevalidator:
    """Internal engine boundary for tests and future trusted engine wiring."""

    if not callable(callback):
        raise TypeError("engine revalidator callback must be callable")
    return EngineRevalidator(callback, _APPLICATION_CAPABILITY)


def create_cleanup_session(plan: CleanupPlan) -> CleanupSession:
    """Create a review session from an immutable engine-generated plan."""

    if not isinstance(plan, CleanupPlan):
        raise TypeError("cleanup sessions require an engine-generated CleanupPlan")
    item_ids = _plan_item_ids(plan)
    plan_digest = _plan_digest(plan)
    review_digest = _review_digest(plan.plan_id, plan_digest, item_ids)
    review = CleanupReview(
        plan.plan_id,
        plan_digest,
        item_ids,
        review_digest,
        _digest((review_digest, "review")),
        _APPLICATION_CAPABILITY,
    )
    return CleanupSession(
        _session_id(plan, review),
        plan,
        review,
        CleanupSessionState.REVIEW_READY,
        _APPLICATION_CAPABILITY,
    )


def create_human_confirmation(
    session: CleanupSession,
    review: CleanupReview,
    *,
    confirmation_phrase: str,
    confirmed_at: str,
) -> HumanConfirmation:
    """Issue confirmation only for the exact session review snapshot."""

    if not isinstance(session, CleanupSession) or not session.is_engine_bound:
        raise ValueError("confirmation requires an engine-bound cleanup session")
    if not isinstance(review, CleanupReview) or review != session.review:
        raise ValueError("confirmation requires the exact unchanged cleanup review")
    if not confirmation_phrase.strip() or not confirmed_at.strip():
        raise ValueError("confirmation requires an explicit phrase and timestamp")
    return HumanConfirmation(
        session.session_id,
        session.plan.plan_id,
        session.review.plan_digest,
        session.review.review_digest,
        session.review.reviewed_item_ids,
        confirmation_phrase,
        confirmed_at,
        _digest((session.session_id, session.review.review_digest, confirmed_at, confirmation_phrase)),
        _APPLICATION_CAPABILITY,
    )


def _confirmation_matches(session: CleanupSession, confirmation: HumanConfirmation) -> bool:
    return (
        isinstance(confirmation, HumanConfirmation)
        and confirmation.is_engine_bound
        and confirmation.session_id == session.session_id
        and confirmation.plan_id == session.plan.plan_id
        and confirmation.plan_digest == session.review.plan_digest
        and confirmation.review_digest == session.review.review_digest
        and confirmation.reviewed_item_ids == session.review.reviewed_item_ids
        and confirmation.confirmation_token == _digest((
            session.session_id,
            session.review.review_digest,
            confirmation.confirmed_at,
            confirmation.confirmation_phrase,
        ))
    )


def _blocked_result(
    session: CleanupSession,
    *,
    state: CleanupSessionState = CleanupSessionState.BLOCKED,
    validation_status: PlanValidationStatus | None = None,
    authorization_status: ExecutionAuthorizationStatus | None = None,
    reconciliation: ReconciliationResult | None = None,
    reason: str,
) -> CleanupApplicationResult:
    return CleanupApplicationResult(
        session.session_id,
        session.plan.plan_id,
        state,
        validation_status,
        authorization_status,
        tuple(
            CleanupItemResult(item.plan_item_id, CleanupItemOutcome.BLOCKED, None, None, reason)
            for item in session.plan.items
        ),
        reconciliation,
        reason,
    )


def _item_results(plan: CleanupPlan, quarantine: QuarantineResult) -> tuple[CleanupItemResult, ...]:
    records = {record.metadata.plan_item_id: record for record in quarantine.records}
    failures = {failure.plan_item_id: failure for failure in quarantine.failures if failure.plan_item_id is not None}
    results: list[CleanupItemResult] = []
    for item in plan.items:
        record = records.get(item.plan_item_id)
        failure = failures.get(item.plan_item_id)
        if record is not None:
            if record.state is QuarantineState.QUARANTINED:
                outcome = CleanupItemOutcome.SUCCEEDED
            elif record.state in {
                QuarantineState.QUARANTINE_COMMITTED_UNJOURNALED,
                QuarantineState.RESTORE_COMMITTED_UNJOURNALED,
            }:
                outcome = CleanupItemOutcome.RECOVERABLE
            else:
                outcome = CleanupItemOutcome.FAILED
            results.append(CleanupItemResult(
                item.plan_item_id,
                outcome,
                record.state,
                record.metadata.recovery_id,
                record.failure_reason,
            ))
            continue
        reason = failure.reason if failure is not None else "item produced no mutation result"
        outcome = (
            CleanupItemOutcome.REPLAYED
            if "replay" in reason.casefold() or "claimed" in reason.casefold()
            else CleanupItemOutcome.FAILED
        )
        results.append(CleanupItemResult(item.plan_item_id, outcome, failure.state if failure else None, None, reason))
    return tuple(results)


def _item_results_from_reconciliation(
    plan: CleanupPlan,
    reconciliation: ReconciliationResult,
    reason: str,
) -> tuple[CleanupItemResult, ...]:
    """Preserve already journaled outcomes after an unexpected mutation error."""

    latest: dict[PlanItemId, object] = {}
    for entry in reconciliation.entries:
        try:
            item_id = PlanItemId(entry.plan_item_id)
        except (TypeError, ValueError):
            continue
        latest[item_id] = entry
    results: list[CleanupItemResult] = []
    for item in plan.items:
        entry = latest.get(item.plan_item_id)
        if entry is None:
            results.append(CleanupItemResult(
                item.plan_item_id,
                CleanupItemOutcome.BLOCKED,
                None,
                None,
                reason,
            ))
            continue
        entry_reason = getattr(entry, "failure_reason", None) or reason
        state = entry.status
        if state is QuarantineState.QUARANTINED:
            outcome = CleanupItemOutcome.SUCCEEDED
        elif state in {
            QuarantineState.QUARANTINE_COMMITTED_UNJOURNALED,
            QuarantineState.RESTORE_COMMITTED_UNJOURNALED,
        }:
            outcome = CleanupItemOutcome.RECOVERABLE
        elif state is QuarantineState.FAILED:
            outcome = (
                CleanupItemOutcome.REPLAYED
                if "replay" in entry_reason.casefold() or "claimed" in entry_reason.casefold()
                else CleanupItemOutcome.FAILED
            )
        else:
            outcome = CleanupItemOutcome.BLOCKED
        results.append(CleanupItemResult(
            item.plan_item_id,
            outcome,
            state,
            entry.recovery_id,
            entry_reason,
        ))
    return tuple(results)


def _application_state_for_items(
    item_results: tuple[CleanupItemResult, ...],
    *,
    default: CleanupSessionState,
    reason: str,
) -> tuple[CleanupSessionState, str]:
    successes = sum(result.outcome is CleanupItemOutcome.SUCCEEDED for result in item_results)
    recoverables = sum(result.outcome is CleanupItemOutcome.RECOVERABLE for result in item_results)
    if successes or recoverables:
        return CleanupSessionState.PARTIAL, "items were processed independently; this operation is not transactional"
    return default, reason


def execute_cleanup_session(
    session: CleanupSession,
    confirmation: HumanConfirmation,
    *,
    engine_revalidator: EngineRevalidator,
    mutation_root: MutationRoot,
    quarantine_root: QuarantineRoot,
    journal: AuditJournal,
    clock=None,
) -> CleanupApplicationResult:
    """Revalidate and execute one confirmed plan without accepting raw paths."""

    if not isinstance(session, CleanupSession) or not session.is_engine_bound:
        raise TypeError("cleanup execution requires an engine-bound CleanupSession")
    if not _confirmation_matches(session, confirmation):
        return _blocked_result(session, reason="missing, forged, stale, or mismatched human confirmation")
    if not isinstance(engine_revalidator, EngineRevalidator):
        return _blocked_result(session, reason="fresh engine revalidation capability is required")
    try:
        reconciliation = reconcile_pending_operations(
            journal,
            mutation_root,
            quarantine_root,
            **({"clock": clock} if clock is not None else {}),
        )
    except Exception as error:
        return _blocked_result(
            session,
            state=CleanupSessionState.RECONCILIATION_REQUIRED,
            reason=f"restart reconciliation failed closed: {error}",
        )
    if reconciliation.failures:
        return _blocked_result(
            session,
            state=CleanupSessionState.RECONCILIATION_REQUIRED,
            reconciliation=reconciliation,
            reason="pending mutation reconciliation requires review before execution",
        )
    if any(recovery.plan_id == session.plan.plan_id.value for recovery in reconciliation.claim_recoveries):
        return _blocked_result(
            session,
            state=CleanupSessionState.RECONCILIATION_REQUIRED,
            reconciliation=reconciliation,
            reason="this plan has an orphan authorization claim and cannot be retried automatically",
        )
    try:
        fresh = engine_revalidator.revalidate(session.plan)
        validation = validate_cleanup_plan(
            session.plan,
            fresh.as_mapping(session.plan),
            scan_context=fresh.scan_context,
        )
    except Exception as error:
        return _blocked_result(
            session,
            reconciliation=reconciliation,
            reason=f"fresh engine revalidation failed closed: {error}",
        )
    if validation.status is not PlanValidationStatus.VALID:
        return _blocked_result(
            session,
            validation_status=validation.status,
            reconciliation=reconciliation,
            reason="fresh post-confirmation revalidation blocked execution",
        )
    authorization = authorize_execution(session.plan, validation)
    if authorization.status is not ExecutionAuthorizationStatus.AUTHORIZED:
        return _blocked_result(
            session,
            validation_status=validation.status,
            authorization_status=authorization.status,
            reconciliation=reconciliation,
            reason="engine authorization was denied",
        )
    try:
        quarantine = quarantine_plan(
            session.plan,
            validation,
            authorization,
            mutation_root,
            quarantine_root,
            journal,
            **({"clock": clock} if clock is not None else {}),
        )
    except Exception as error:
        try:
            recovered = reconcile_pending_operations(
                journal,
                mutation_root,
                quarantine_root,
                **({"clock": clock} if clock is not None else {}),
            )
        except Exception as recovery_error:
            return _blocked_result(
                session,
                validation_status=validation.status,
                authorization_status=authorization.status,
                reconciliation=reconciliation,
                reason=f"mutation failed and recovery was inconclusive: {error}; {recovery_error}",
            )
        item_results = _item_results_from_reconciliation(
            session.plan,
            recovered,
            f"mutation raised unexpectedly; item was not confirmed complete: {error}",
        )
        state, reason = _application_state_for_items(
            item_results,
            default=CleanupSessionState.RECONCILIATION_REQUIRED if recovered.failures else CleanupSessionState.BLOCKED,
            reason=f"mutation failed conservatively: {error}",
        )
        return CleanupApplicationResult(
            session.session_id,
            session.plan.plan_id,
            state,
            validation.status,
            authorization.status,
            item_results,
            recovered,
            reason,
        )
    item_results = _item_results(session.plan, quarantine)
    successes = sum(result.outcome is CleanupItemOutcome.SUCCEEDED for result in item_results)
    recoverables = sum(result.outcome is CleanupItemOutcome.RECOVERABLE for result in item_results)
    failures = len(item_results) - successes - recoverables
    if failures == 0 and recoverables == 0 and item_results:
        state = CleanupSessionState.EXECUTED
        reason = None
    elif successes or recoverables:
        state = CleanupSessionState.PARTIAL
        reason = "items were processed independently; this operation is not transactional"
    else:
        state = CleanupSessionState.REPLAYED if any(
            result.outcome is CleanupItemOutcome.REPLAYED for result in item_results
        ) else CleanupSessionState.BLOCKED
        reason = "no cleanup item was successfully quarantined"
    return CleanupApplicationResult(
        session.session_id,
        session.plan.plan_id,
        state,
        validation.status,
        authorization.status,
        item_results,
        reconciliation,
        reason,
    )
