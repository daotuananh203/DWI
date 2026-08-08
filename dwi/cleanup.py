"""Pure, immutable contracts for future safe-cleanup planning.

This module intentionally performs no filesystem access and no mutation. Callers
must supply current observations and findings; the future executor will be the
only layer allowed to perform a reversible mutation after authorization.
"""

from __future__ import annotations

import hashlib
import json
import ntpath
import os
from threading import Lock
from dataclasses import dataclass, field, replace
from enum import Enum
from typing import Iterable, Mapping

from .contracts import ArtifactKind
from .domain import (
    ActionEligibility,
    ActivityState,
    EvidenceBundle,
    NodeKind,
    ProtectionClass,
    ReachabilityState,
    RegenerabilityState,
    RiskLabel,
    RuleTrace,
)
from .pipeline import CandidateEligibility, Finding
from .size import SizeObservation


class MutationIntent(str, Enum):
    QUARANTINE = "quarantine"


class ScanCompleteness(str, Enum):
    COMPLETE = "complete"
    PARTIAL = "partial"
    FAILED = "failed"
    UNKNOWN = "unknown"


class PlanValidationStatus(str, Enum):
    VALID = "valid"
    STALE_CHANGED = "stale_changed"
    BLOCKED = "blocked"
    FAILED_INCONCLUSIVE = "failed_inconclusive"


class ExecutionAuthorizationStatus(str, Enum):
    AUTHORIZED = "authorized"
    DENIED = "denied"


class QuarantineState(str, Enum):
    AUTHORIZATION_CLAIMED = "authorization_claimed"
    PLANNED = "planned"
    QUARANTINING = "quarantining"
    QUARANTINE_COMMITTED_UNJOURNALED = "quarantine_committed_unjournaled"
    QUARANTINED = "quarantined"
    RESTORING = "restoring"
    RESTORE_COMMITTED_UNJOURNALED = "restore_committed_unjournaled"
    RESTORED = "restored"
    FAILED = "failed"


_ENGINE_SCAN_CAPABILITY = object()
_ENGINE_VALIDATION_CAPABILITY = object()
_ENGINE_AUTHORIZATION_CAPABILITY = object()


def _canonical_absolute_path(path: str) -> str | None:
    """Return a conservative Windows absolute path without resolving links."""

    if not isinstance(path, str) or not path.strip():
        return None
    if not ntpath.isabs(path):
        return None
    drive, tail = ntpath.splitdrive(path)
    if not drive:
        return None
    components = tail.replace("/", "\\").split("\\")
    if any(component in {".", ".."} for component in components):
        return None
    return ntpath.normcase(ntpath.normpath(path))


def _path_is_within(path: str, root: str) -> bool:
    canonical_path = _canonical_absolute_path(path)
    canonical_root = _canonical_absolute_path(root)
    if canonical_path is None or canonical_root is None:
        return False
    return canonical_path == canonical_root or canonical_path.startswith(canonical_root.rstrip("\\") + "\\")


@dataclass(frozen=True)
class ApprovedRoot:
    """An engine-derived canonical root binding for a cleanup plan."""

    path: str
    scan_provenance: str
    _capability: object | None = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        canonical = _canonical_absolute_path(self.path)
        if canonical is None:
            raise ValueError("approved root must be an absolute normalized Windows path")
        if not self.scan_provenance.strip():
            raise ValueError("approved root must identify its scan provenance")
        object.__setattr__(self, "path", canonical)

    @property
    def is_engine_trusted(self) -> bool:
        return self._capability is _ENGINE_SCAN_CAPABILITY


@dataclass(frozen=True)
class TrustedScanContext:
    """Engine-issued completeness and root provenance for planning/revalidation."""

    completeness: ScanCompleteness
    scan_provenance: str
    approved_roots: tuple[ApprovedRoot, ...]
    _capability: object | None = field(default=None, repr=False, compare=False)

    @property
    def is_engine_trusted(self) -> bool:
        return self._capability is _ENGINE_SCAN_CAPABILITY

    def includes_root(self, root: ApprovedRoot) -> bool:
        return (
            self.is_engine_trusted
            and root.is_engine_trusted
            and root.scan_provenance == self.scan_provenance
            and root in self.approved_roots
        )


@dataclass(frozen=True)
class _ValidationProof:
    capability: object
    plan_digest: str
    snapshot_digest: str
    scan_provenance: str
    public_digest: str
    validated_snapshots: tuple[tuple[PlanItemId, FindingSnapshot], ...] = ()


class _AuthorizationConsumption:
    """Private one-shot ledger shared by copies of one engine authorization."""

    def __init__(self, plan_id: PlanId, item_ids: tuple[PlanItemId, ...]) -> None:
        self.plan_id = plan_id
        self.item_ids = item_ids
        self._consumed: set[PlanItemId] = set()
        self._lock = Lock()

    def consume(self, plan_id: PlanId, item_id: PlanItemId) -> bool:
        with self._lock:
            if plan_id != self.plan_id or item_id not in self.item_ids or item_id in self._consumed:
                return False
            self._consumed.add(item_id)
            return True

    def is_consumed(self, item_id: PlanItemId) -> bool:
        with self._lock:
            return item_id in self._consumed


@dataclass(frozen=True)
class PlanId:
    value: str

    def __post_init__(self) -> None:
        if not self.value.strip():
            raise ValueError("plan id must not be empty")


@dataclass(frozen=True)
class PlanItemId:
    value: str

    def __post_init__(self) -> None:
        if not self.value.strip():
            raise ValueError("plan item id must not be empty")


@dataclass(frozen=True)
class FilesystemIdentity:
    """The identity/type observation required for later revalidation."""

    device: int | None
    inode: int | None
    object_type: NodeKind
    is_reparse: bool
    authoritative_path: str | None = None

    def __post_init__(self) -> None:
        for name, value in (("device", self.device), ("inode", self.inode)):
            if value is not None and (isinstance(value, bool) or not isinstance(value, int) or value <= 0):
                raise ValueError(f"filesystem {name} identity must be a positive integer or None")
        if self.authoritative_path is not None:
            canonical = _canonical_absolute_path(self.authoritative_path)
            if canonical is None:
                raise ValueError("authoritative filesystem path must be an absolute normalized Windows path")
            object.__setattr__(self, "authoritative_path", canonical)

    @property
    def is_suitable_for_planning(self) -> bool:
        return (
            isinstance(self.device, int)
            and not isinstance(self.device, bool)
            and self.device > 0
            and isinstance(self.inode, int)
            and not isinstance(self.inode, bool)
            and self.inode > 0
            and self.object_type is NodeKind.DIRECTORY
            and not self.is_reparse
            and self.authoritative_path is not None
        )

    @property
    def has_authoritative_path(self) -> bool:
        return self.authoritative_path is not None


@dataclass(frozen=True)
class FindingSnapshot:
    """The exact finding and observation state captured by a plan item."""

    artifact: ArtifactKind
    path: str
    filesystem_identity: FilesystemIdentity
    risk_label: RiskLabel
    action_eligibility: ActionEligibility
    regenerability: RegenerabilityState
    reachability: ReachabilityState
    activity: ActivityState
    protection: ProtectionClass
    evidence: EvidenceBundle
    rule_trace: RuleTrace | None
    size: SizeObservation

    def __post_init__(self) -> None:
        canonical = _canonical_absolute_path(self.path)
        if canonical is None:
            raise ValueError("finding snapshot path must be absolute and normalized")
        object.__setattr__(self, "path", canonical)

    @classmethod
    def from_finding(cls, finding: Finding, filesystem_identity: FilesystemIdentity) -> "FindingSnapshot":
        decision = finding.safety_decision
        return cls(
            artifact=finding.artifact,
            path=finding.path,
            filesystem_identity=filesystem_identity,
            risk_label=finding.risk_label,
            action_eligibility=finding.action_eligibility,
            regenerability=finding.interpretation.regenerability,
            reachability=finding.interpretation.reachability,
            activity=finding.interpretation.activity,
            protection=finding.interpretation.protection,
            evidence=finding.evidence,
            rule_trace=decision.rule_trace if decision is not None else None,
            size=finding.size,
        )


@dataclass(frozen=True)
class PlanExclusion:
    artifact: ArtifactKind
    path: str
    reason: str


@dataclass(frozen=True)
class CleanupPlanItem:
    plan_item_id: PlanItemId
    snapshot: FindingSnapshot
    mutation_intent: MutationIntent


@dataclass(frozen=True)
class CleanupPlan:
    """An engine-generated proposal, never an execution authorization."""

    plan_id: PlanId
    items: tuple[CleanupPlanItem, ...]
    exclusions: tuple[PlanExclusion, ...]
    mutation_intent: MutationIntent
    engine_version: str
    approved_root: ApprovedRoot
    scan_context: TrustedScanContext
    origin: str = "engine-generated-from-findings"

    def __post_init__(self) -> None:
        if not self.engine_version.strip():
            raise ValueError("cleanup plan engine version must not be empty")
        if self.origin != "engine-generated-from-findings":
            raise ValueError("cleanup plans must identify the engine-generated finding origin")
        if not self.scan_context.is_engine_trusted or not self.approved_root.is_engine_trusted:
            raise ValueError("cleanup plans require engine-issued scan context and root binding")
        if not self.scan_context.includes_root(self.approved_root):
            raise ValueError("cleanup plan root is not bound to its trusted scan context")
        ids = [item.plan_item_id for item in self.items]
        if len(ids) != len(set(ids)):
            raise ValueError("cleanup plan item identifiers must be unique")


@dataclass(frozen=True)
class ValidationFailure:
    code: str
    reason: str
    plan_item_id: PlanItemId | None = None


@dataclass(frozen=True)
class PlanValidation:
    plan_id: PlanId
    status: PlanValidationStatus
    failures: tuple[ValidationFailure, ...]
    validation_token: str
    _proof: _ValidationProof | None = field(default=None, repr=False, compare=False)

    @property
    def is_valid(self) -> bool:
        return (
            self.status is PlanValidationStatus.VALID
            and self._proof is not None
            and self._proof.capability is _ENGINE_VALIDATION_CAPABILITY
            and self._proof.public_digest == _validation_public_digest(self)
        )


@dataclass(frozen=True)
class ExecutionAuthorization:
    """Engine permission metadata; it does not perform or trigger execution."""

    plan_id: PlanId
    validation_token: str
    status: ExecutionAuthorizationStatus
    authorized_item_ids: tuple[PlanItemId, ...]
    authorization_token: str
    reason: str
    plan_digest: str = ""
    validation_state_digest: str = ""
    _capability: object | None = field(default=None, repr=False, compare=False)
    _authorization_digest: str = field(default="", repr=False, compare=False)
    _consumption: _AuthorizationConsumption | None = field(default=None, repr=False, compare=False)

    @property
    def is_authorized(self) -> bool:
        return (
            self.status is ExecutionAuthorizationStatus.AUTHORIZED
            and self._capability is _ENGINE_AUTHORIZATION_CAPABILITY
            and self._authorization_digest == _authorization_public_digest(self)
            and self._consumption is not None
            and any(not self._consumption.is_consumed(item_id) for item_id in self.authorized_item_ids)
        )

    def matches_validation(self, validation: PlanValidation) -> bool:
        proof = validation._proof if isinstance(validation, PlanValidation) else None
        return (
            self.is_authorized
            and isinstance(validation, PlanValidation)
            and validation.is_valid
            and self.plan_id == validation.plan_id
            and self.validation_token == validation.validation_token
            and proof is not None
            and proof.capability is _ENGINE_VALIDATION_CAPABILITY
            and proof.plan_digest == self.plan_digest
            and proof.public_digest == self.validation_state_digest
            and _validation_public_digest(validation) == self.validation_state_digest
        )

    def _consume_item(self, plan_id: PlanId, item_id: PlanItemId) -> bool:
        return (
            self.is_authorized
            and self._consumption is not None
            and self._consumption.consume(plan_id, item_id)
        )


@dataclass(frozen=True)
class RecoveryMetadata:
    recovery_id: str
    original_path: str
    quarantine_path: str | None
    plan_id: PlanId
    plan_item_id: PlanItemId
    planned_at: str
    completed_at: str | None = None
    original_identity: FilesystemIdentity | None = None


@dataclass(frozen=True)
class QuarantineRecord:
    metadata: RecoveryMetadata
    state: QuarantineState
    failure_reason: str | None = None


def _serializable(value: object) -> object:
    if isinstance(value, Enum):
        return value.value
    if hasattr(value, "value") and type(value).__name__ in {"PlanId", "PlanItemId"}:
        return getattr(value, "value")
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    if isinstance(value, tuple):
        return [_serializable(item) for item in value]
    if isinstance(value, list):
        return [_serializable(item) for item in value]
    if isinstance(value, dict):
        return {str(key): _serializable(item) for key, item in sorted(value.items(), key=lambda item: str(item[0]))}
    if hasattr(value, "__dataclass_fields__"):
        return {
            name: _serializable(getattr(value, name))
            for name in value.__dataclass_fields__
            if not name.startswith("_")
        }
    return str(value)


def _canonical(value: object) -> str:
    return json.dumps(_serializable(value), sort_keys=True, separators=(",", ":"))


def _digest(value: object) -> str:
    return hashlib.sha256(_canonical(value).encode("utf-8")).hexdigest()


def _validation_public_digest(validation: PlanValidation) -> str:
    return _digest((validation.plan_id, validation.status, validation.failures, validation.validation_token))


def _authorization_public_digest(authorization: ExecutionAuthorization) -> str:
    return _digest((
        authorization.plan_id,
        authorization.validation_token,
        authorization.status,
        authorization.authorized_item_ids,
        authorization.plan_digest,
        authorization.validation_state_digest,
    ))


def _path_key(path: str) -> str:
    canonical = _canonical_absolute_path(path)
    return canonical if canonical is not None else os.path.normcase(os.path.abspath(path))


def _trusted_scan_context(
    completeness: ScanCompleteness,
    scan_provenance: str,
    roots: tuple[str, ...],
) -> TrustedScanContext:
    approved_roots = tuple(
        ApprovedRoot(path, scan_provenance, _ENGINE_SCAN_CAPABILITY)
        for path in sorted(set(roots), key=lambda item: (item.casefold(), item))
    )
    return TrustedScanContext(
        completeness,
        scan_provenance,
        approved_roots,
        _ENGINE_SCAN_CAPABILITY,
    )


def scan_context_from_system_scan(scan: object) -> TrustedScanContext:
    """Create engine-issued planning context from one structured SystemScan."""

    from .system_scan import RootStatus, SystemScan

    if not isinstance(scan, SystemScan):
        raise TypeError("trusted scan context requires an engine SystemScan result")
    completeness = scan_completeness_from_system_scan(scan)
    provenance = _digest((scan.requested_roots, scan.root_observations, scan.termination, scan.observation_failures))
    observed_roots = tuple(
        item.path
        for item in scan.root_observations
        if item.status not in {RootStatus.DENIED, RootStatus.SKIPPED}
    )
    return _trusted_scan_context(completeness, provenance, observed_roots)


def snapshot_from_finding(
    finding: Finding,
    filesystem_identity: FilesystemIdentity,
    *,
    canonical_path: str | None = None,
) -> FindingSnapshot:
    return FindingSnapshot(
        artifact=finding.artifact,
        path=canonical_path or finding.path,
        filesystem_identity=filesystem_identity,
        risk_label=finding.risk_label,
        action_eligibility=finding.action_eligibility,
        regenerability=finding.interpretation.regenerability,
        reachability=finding.interpretation.reachability,
        activity=finding.interpretation.activity,
        protection=finding.interpretation.protection,
        evidence=finding.evidence,
        rule_trace=finding.safety_decision.rule_trace if finding.safety_decision is not None else None,
        size=finding.size,
    )


def _exclusion(finding: Finding, reason: str) -> PlanExclusion:
    return PlanExclusion(finding.artifact, finding.path, reason)


def create_cleanup_plan(
    findings: Iterable[Finding],
    *,
    filesystem_identities: Mapping[str, FilesystemIdentity],
    scan_context: TrustedScanContext,
    approved_root: ApprovedRoot,
    mutation_intent: MutationIntent = MutationIntent.QUARANTINE,
    engine_version: str = "dwi-cleanup-0.1",
) -> CleanupPlan:
    """Create a proposal only from complete, policy-eligible Findings.

    ``filesystem_identities`` are observations supplied by the caller; this
    pure function never reads paths. A partial, failed, unknown, or omitted
    trusted scan context cannot establish cleanup-plan safety.
    """

    if not isinstance(scan_context, TrustedScanContext) or not scan_context.is_engine_trusted:
        raise TypeError("cleanup planning requires an engine-issued TrustedScanContext")
    if not isinstance(approved_root, ApprovedRoot) or not approved_root.is_engine_trusted:
        raise TypeError("cleanup planning requires an engine-issued ApprovedRoot")
    if not scan_context.includes_root(approved_root):
        raise ValueError("approved root is not bound to the trusted scan context")

    items: list[CleanupPlanItem] = []
    exclusions: list[PlanExclusion] = []
    finding_list = tuple(findings)
    if any(not isinstance(finding, Finding) for finding in finding_list):
        raise TypeError("cleanup plans accept Finding objects, not arbitrary path records")
    for finding in sorted(finding_list, key=lambda item: (item.path.casefold(), item.path, item.artifact.value)):
        if scan_context.completeness is not ScanCompleteness.COMPLETE:
            exclusions.append(_exclusion(finding, f"scan is {scan_context.completeness.value}; unvisited state is not safe for planning"))
            continue
        canonical_path = _canonical_absolute_path(finding.path)
        if canonical_path is None:
            exclusions.append(_exclusion(finding, "candidate path must be absolute and normalized"))
            continue
        if not _path_is_within(canonical_path, approved_root.path):
            exclusions.append(_exclusion(finding, "candidate path is outside the approved root binding"))
            continue
        identity = filesystem_identities.get(_path_key(canonical_path)) or filesystem_identities.get(finding.path)
        if identity is None:
            exclusions.append(_exclusion(finding, "planning requires a filesystem identity snapshot"))
            continue
        if finding.candidate_selection.eligibility is not CandidateEligibility.SELECTED:
            exclusions.append(_exclusion(finding, "candidate selection rejected the finding"))
            continue
        if finding.safety_decision is None:
            exclusions.append(_exclusion(finding, "a Safety Policy decision is required"))
            continue
        if finding.risk_label in {RiskLabel.REVIEW_REQUIRED, RiskLabel.NEVER_DELETE}:
            exclusions.append(_exclusion(finding, f"risk label {finding.risk_label.value} is not executable"))
            continue
        if finding.action_eligibility is not ActionEligibility.ELIGIBLE_FOR_EXPLICIT_ACTION:
            exclusions.append(_exclusion(finding, "action eligibility is not explicitly eligible"))
            continue
        if not identity.is_suitable_for_planning:
            exclusions.append(_exclusion(finding, "filesystem identity is incomplete, non-directory, reparse-backed, or lacks authoritative path"))
            continue
        if not finding.evidence.is_complete or finding.evidence.has_uncertainty or finding.evidence.has_conflicts:
            exclusions.append(_exclusion(finding, "required safety evidence is incomplete, failed, uncertain, or conflicting"))
            continue
        if finding.interpretation.protection is not ProtectionClass.ORDINARY:
            exclusions.append(_exclusion(finding, "protection evidence vetoes mutation planning"))
            continue
        if finding.interpretation.reachability is not ReachabilityState.CONFIRMED_UNREFERENCED:
            exclusions.append(_exclusion(finding, "reachability is not confirmed absent"))
            continue
        if finding.interpretation.activity is not ActivityState.INACTIVE:
            exclusions.append(_exclusion(finding, "activity is not confirmed inactive"))
            continue
        if not finding.size.complete:
            exclusions.append(_exclusion(finding, "size/evidence observation is incomplete"))
            continue
        snapshot = snapshot_from_finding(finding, identity, canonical_path=canonical_path)
        item_id = PlanItemId(f"item-{_digest(snapshot)}")
        items.append(CleanupPlanItem(item_id, snapshot, mutation_intent))

    item_payload = tuple(items)
    plan_id = PlanId(f"plan-{_digest((engine_version, mutation_intent, approved_root, scan_context, item_payload, tuple(exclusions)))}")
    return CleanupPlan(
        plan_id,
        item_payload,
        tuple(exclusions),
        mutation_intent,
        engine_version,
        approved_root,
        scan_context,
    )


def _snapshot_differences(planned: FindingSnapshot, current: FindingSnapshot) -> tuple[str, ...]:
    differences: list[str] = []
    fields = (
        "artifact", "risk_label", "action_eligibility", "regenerability", "reachability",
        "activity", "protection", "evidence", "rule_trace", "size", "filesystem_identity",
    )
    if _path_key(planned.path) != _path_key(current.path):
        differences.append("path")
    for field in fields:
        if getattr(planned, field) != getattr(current, field):
            differences.append(field)
    return tuple(differences)


def validate_cleanup_plan(
    plan: CleanupPlan,
    current_snapshots: Mapping[PlanItemId, FindingSnapshot],
    *,
    scan_context: TrustedScanContext,
) -> PlanValidation:
    """Perform deterministic comparison of planned and current snapshots."""

    if not isinstance(plan, CleanupPlan):
        raise TypeError("plan validation requires a CleanupPlan")
    if not isinstance(scan_context, TrustedScanContext) or not scan_context.is_engine_trusted:
        raise TypeError("plan validation requires an engine-issued TrustedScanContext")

    failures: list[ValidationFailure] = []
    expected_item_ids = {item.plan_item_id for item in plan.items}
    supplied_item_ids = set(current_snapshots)
    if supplied_item_ids != expected_item_ids:
        failures.append(ValidationFailure(
            "snapshot-set-mismatch",
            "immediate validation must contain exactly the plan item snapshots",
        ))
    if scan_context.completeness is not ScanCompleteness.COMPLETE:
        failures.append(ValidationFailure(
            "scan-incomplete",
            f"current scan is {scan_context.completeness.value}; validation is inconclusive",
        ))
    if not scan_context.includes_root(plan.approved_root):
        failures.append(ValidationFailure(
            "root-veto",
            "current trusted scan does not cover the plan's approved root",
        ))
    for item in plan.items:
        current = current_snapshots.get(item.plan_item_id)
        if current is None:
            failures.append(ValidationFailure(
                "missing-current-snapshot",
                "the planned item could not be immediately re-observed",
                item.plan_item_id,
            ))
            continue
        if not _path_is_within(current.path, plan.approved_root.path):
            failures.append(ValidationFailure(
                "root-veto",
                "current snapshot path is outside the approved root",
                item.plan_item_id,
            ))
        if not current.filesystem_identity.is_suitable_for_planning:
            failures.append(ValidationFailure(
                "identity-veto",
                "current filesystem identity is missing, invalid, reparse-backed, or lacks authoritative path",
                item.plan_item_id,
            ))
        if not current.evidence.is_complete or current.evidence.has_uncertainty or current.evidence.has_conflicts:
            failures.append(ValidationFailure(
                "evidence-veto",
                "current required evidence is incomplete, uncertain, or conflicting",
                item.plan_item_id,
            ))
        if not current.size.complete:
            failures.append(ValidationFailure(
                "size-veto",
                "current size observation is incomplete",
                item.plan_item_id,
            ))
        if current.risk_label in {RiskLabel.REVIEW_REQUIRED, RiskLabel.NEVER_DELETE}:
            failures.append(ValidationFailure(
                "risk-veto",
                "current Safety Policy posture blocks execution",
                item.plan_item_id,
            ))
        elif current.action_eligibility is not ActionEligibility.ELIGIBLE_FOR_EXPLICIT_ACTION:
            failures.append(ValidationFailure(
                "action-veto",
                "current ActionEligibility is not explicitly eligible",
                item.plan_item_id,
            ))
        elif current.protection is not ProtectionClass.ORDINARY:
            failures.append(ValidationFailure(
                "protection-veto",
                "current protection state blocks execution",
                item.plan_item_id,
            ))
        elif current.reachability is not ReachabilityState.CONFIRMED_UNREFERENCED:
            failures.append(ValidationFailure(
                "reachability-veto",
                "current reachability is not confirmed absent",
                item.plan_item_id,
            ))
        elif current.activity is not ActivityState.INACTIVE:
            failures.append(ValidationFailure(
                "activity-veto",
                "current activity is not confirmed inactive",
                item.plan_item_id,
            ))
        differences = _snapshot_differences(item.snapshot, current)
        if differences:
            failures.append(ValidationFailure(
                "snapshot-changed",
                "material planned state changed: " + ", ".join(differences),
                item.plan_item_id,
            ))

    failures_tuple = tuple(sorted(failures, key=lambda item: (item.plan_item_id.value if item.plan_item_id else "", item.code, item.reason)))
    if any(failure.code.endswith("veto") or failure.code == "scan-incomplete" for failure in failures_tuple):
        status = PlanValidationStatus.BLOCKED
    elif any(failure.code == "snapshot-changed" for failure in failures_tuple):
        status = PlanValidationStatus.STALE_CHANGED
    elif failures_tuple:
        status = PlanValidationStatus.FAILED_INCONCLUSIVE
    else:
        status = PlanValidationStatus.VALID
    ordered_snapshots = tuple(sorted(current_snapshots.items(), key=lambda item: item[0].value))
    snapshot_digest = _digest(ordered_snapshots)
    token = _digest((plan, status, failures_tuple, ordered_snapshots, scan_context))
    public_digest = _digest((plan.plan_id, status, failures_tuple, token))
    proof = _ValidationProof(
        _ENGINE_VALIDATION_CAPABILITY,
        _digest(plan),
        snapshot_digest,
        scan_context.scan_provenance,
        public_digest,
        tuple(sorted(current_snapshots.items(), key=lambda item: item[0].value)),
    )
    return PlanValidation(plan.plan_id, status, failures_tuple, token, proof)


def authorize_execution(plan: CleanupPlan, validation: PlanValidation) -> ExecutionAuthorization:
    """Grant metadata-only authorization after a valid immediate validation."""

    if not isinstance(plan, CleanupPlan):
        raise TypeError("execution authorization requires a CleanupPlan")
    proof = validation._proof if isinstance(validation, PlanValidation) else None
    validation_token = validation.validation_token if isinstance(validation, PlanValidation) else ""
    validation_digest = _validation_public_digest(validation) if isinstance(validation, PlanValidation) else ""
    authentic = (
        isinstance(validation, PlanValidation)
        and proof is not None
        and proof.capability is _ENGINE_VALIDATION_CAPABILITY
        and proof.plan_digest == _digest(plan)
        and proof.public_digest == validation_digest
        and proof.validated_snapshots == tuple(sorted(
            ((item.plan_item_id, item.snapshot) for item in plan.items),
            key=lambda item: item[0].value,
        ))
    )
    if not authentic or not isinstance(validation, PlanValidation) or validation.plan_id != plan.plan_id or not validation.is_valid or not plan.items:
        authorization = ExecutionAuthorization(
            plan.plan_id,
            validation_token,
            ExecutionAuthorizationStatus.DENIED,
            (),
            _digest((plan.plan_id, validation_token, "denied")),
            "Execution requires a valid non-empty engine-generated plan validation.",
            _digest(plan),
            validation_digest,
            _ENGINE_AUTHORIZATION_CAPABILITY,
        )
        return replace(authorization, _authorization_digest=_authorization_public_digest(authorization))
    item_ids = tuple(item.plan_item_id for item in plan.items)
    authorization = ExecutionAuthorization(
        plan.plan_id,
        validation.validation_token,
        ExecutionAuthorizationStatus.AUTHORIZED,
        item_ids,
        _digest((plan.plan_id, validation.validation_token, item_ids)),
        "Execution authorization granted for the validated plan state; no mutation was performed.",
        _digest(plan),
        validation_digest,
        _ENGINE_AUTHORIZATION_CAPABILITY,
        "",
        _AuthorizationConsumption(plan.plan_id, item_ids),
    )
    return replace(authorization, _authorization_digest=_authorization_public_digest(authorization))


def plan_to_json(plan: CleanupPlan) -> str:
    return _canonical(plan)


def validation_to_json(validation: PlanValidation) -> str:
    return _canonical(validation)


def authorization_to_json(authorization: ExecutionAuthorization) -> str:
    return _canonical(authorization)


def scan_completeness_from_system_scan(scan: object) -> ScanCompleteness:
    """Map a SystemScan-like result without allowing partial roots to pass."""

    from .system_scan import SystemScan

    if not isinstance(scan, SystemScan):
        return ScanCompleteness.UNKNOWN
    termination = getattr(scan, "termination", None)
    if getattr(termination, "value", termination) != "completed":
        return ScanCompleteness.PARTIAL
    if not scan.root_observations:
        return ScanCompleteness.UNKNOWN
    if scan.observation_failures or scan.ambiguous_boundaries:
        return ScanCompleteness.PARTIAL
    observations = getattr(scan, "root_observations", ())
    statuses = {getattr(item.status, "value", item.status) for item in observations}
    if "failed" in statuses:
        return ScanCompleteness.FAILED
    # ``scanned`` is a legacy/unclassified observation marker, not proof that
    # all required evidence was complete. Mutation planning therefore fails
    # closed until the scanner emits explicit COMPLETE.
    if statuses - {"complete"} or "partial" in statuses:
        return ScanCompleteness.PARTIAL
    return ScanCompleteness.COMPLETE
