"""Immutable domain vocabulary and evidence schema for DWI.

This module contains no filesystem access. Paths are represented as synthetic or
observed identifiers; filesystem scanning and artifact detection live in separate
bounded layers.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class ObservationStatus(str, Enum):
    OBSERVED = "observed"
    NOT_OBSERVED = "not_observed"
    CONFIRMED_ABSENT = "confirmed_absent"
    FAILED = "failed"
    TIMED_OUT = "timed_out"
    INACCESSIBLE = "inaccessible"
    UNKNOWN = "unknown"


class EvidencePolarity(str, Enum):
    SUPPORTS = "supports"
    CONTRADICTS = "contradicts"
    UNKNOWN = "unknown"
    CONFLICTING = "conflicting"


class Confidence(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNKNOWN = "unknown"

    @property
    def rank(self) -> int:
        return {
            Confidence.UNKNOWN: 0,
            Confidence.LOW: 1,
            Confidence.MEDIUM: 2,
            Confidence.HIGH: 3,
        }[self]

    def meets(self, minimum: "Confidence") -> bool:
        return minimum is not Confidence.UNKNOWN and self.rank >= minimum.rank


@dataclass(frozen=True)
class EvidenceRequirement:
    """Detector-neutral requirement for one evidence key and its minimum strength."""

    key: str
    minimum_confidence: Confidence

    def __post_init__(self) -> None:
        if not self.key.strip():
            raise ValueError("evidence requirement key must not be empty")
        if self.minimum_confidence is Confidence.UNKNOWN:
            raise ValueError("evidence requirement needs a known minimum confidence")


class RegenerabilityState(str, Enum):
    """Reproducibility evidence/property, not a safety-policy conclusion."""

    REPRODUCIBLE = "reproducible"
    CONDITIONALLY_REPRODUCIBLE = "conditionally_reproducible"
    NOT_REPRODUCIBLE = "not_reproducible"
    UNKNOWN = "unknown"
    CONFLICTING = "conflicting"


class RegenerationCost(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    UNKNOWN = "unknown"


class ReachabilityState(str, Enum):
    CONFIRMED_REFERENCED = "confirmed_referenced"
    CONFIRMED_UNREFERENCED = "confirmed_unreferenced"
    UNKNOWN = "unknown"
    CONFLICTING = "conflicting"


class ActivityState(str, Enum):
    ACTIVE_RUNTIME = "active_runtime"
    INACTIVE = "inactive"
    UNKNOWN = "unknown"
    CONFLICTING = "conflicting"


class ProtectionClass(str, Enum):
    ORDINARY = "ordinary"
    PROTECTED = "protected"
    SYSTEM_PROTECTED = "system_protected"
    REPOSITORY_PROTECTED = "repository_protected"
    UNKNOWN = "unknown"
    CONFLICTING = "conflicting"


class RiskLabel(str, Enum):
    SAFE = "safe"
    REGENERATABLE = "regeneratable"
    REVIEW_REQUIRED = "review_required"
    NEVER_DELETE = "never_delete"

    @property
    def rank(self) -> int:
        return {
            RiskLabel.SAFE: 0,
            RiskLabel.REGENERATABLE: 1,
            RiskLabel.REVIEW_REQUIRED: 2,
            RiskLabel.NEVER_DELETE: 3,
        }[self]


class ActionEligibility(str, Enum):
    BLOCKED = "blocked"
    REQUIRES_REVIEW = "requires_review"
    ELIGIBLE_FOR_EXPLICIT_ACTION = "eligible_for_explicit_action"


class ReclaimPriority(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    UNKNOWN = "unknown"


class NodeKind(str, Enum):
    FILE = "file"
    DIRECTORY = "directory"
    SYMLINK = "symlink"
    JUNCTION = "junction"
    REPARSE_POINT = "reparse_point"
    INACCESSIBLE = "inaccessible"
    UNKNOWN = "unknown"
    GIT_DIRECTORY = "git_directory"
    GIT_FILE = "git_file"


class RuleOutcome(str, Enum):
    PASSED = "passed"
    ESCALATED = "escalated"
    BLOCKED = "blocked"


@dataclass(frozen=True)
class RuleTraceEntry:
    rule_id: str
    outcome: RuleOutcome
    reason: str
    evidence_keys: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.rule_id.strip():
            raise ValueError("rule id must not be empty")
        if not self.reason.strip():
            raise ValueError("rule trace reason must not be empty")


@dataclass(frozen=True)
class RuleTrace:
    engine_version: str
    entries: tuple[RuleTraceEntry, ...] = ()

    def __post_init__(self) -> None:
        if not self.engine_version.strip():
            raise ValueError("rule engine version must not be empty")


@dataclass(frozen=True)
class Provenance:
    ecosystem: str
    generator: str
    confidence: Confidence
    evidence_keys: tuple[str, ...] = ()

    @property
    def is_known(self) -> bool:
        return bool(self.ecosystem and self.generator) and self.confidence is not Confidence.UNKNOWN

    def meets_confidence(self, minimum: Confidence) -> bool:
        return self.is_known and self.confidence.meets(minimum)


@dataclass(frozen=True)
class Evidence:
    key: str
    source: str
    description: str
    observation_status: ObservationStatus
    polarity: EvidencePolarity
    confidence: Confidence
    value: str | None = None

    def __post_init__(self) -> None:
        if not self.key.strip():
            raise ValueError("evidence key must not be empty")
        if not self.source.strip():
            raise ValueError("evidence source must not be empty")
        if not self.description.strip():
            raise ValueError("evidence description must not be empty")
        if self.observation_status is ObservationStatus.NOT_OBSERVED and self.polarity is not EvidencePolarity.UNKNOWN:
            raise ValueError("NOT_OBSERVED evidence cannot claim a directional result")
        if self.observation_status is ObservationStatus.CONFIRMED_ABSENT and self.polarity is not EvidencePolarity.CONTRADICTS:
            raise ValueError("CONFIRMED_ABSENT evidence must use CONTRADICTS polarity")
        if self.polarity is EvidencePolarity.CONTRADICTS and self.observation_status is not ObservationStatus.CONFIRMED_ABSENT:
            raise ValueError("CONTRADICTS evidence requires an active confirmed-absence check")

    @property
    def is_observation_failure(self) -> bool:
        return self.observation_status in {
            ObservationStatus.NOT_OBSERVED,
            ObservationStatus.FAILED,
            ObservationStatus.TIMED_OUT,
            ObservationStatus.INACCESSIBLE,
            ObservationStatus.UNKNOWN,
        }

    @property
    def is_uncertain(self) -> bool:
        return self.is_observation_failure or self.polarity in {
            EvidencePolarity.UNKNOWN,
            EvidencePolarity.CONFLICTING,
        } or self.confidence is Confidence.UNKNOWN

    def meets_requirement(self, requirement: EvidenceRequirement) -> bool:
        return (
            not self.is_uncertain
            and self.confidence.meets(requirement.minimum_confidence)
        )


@dataclass(frozen=True)
class EvidenceBundle:
    observations: tuple[Evidence, ...] = ()
    requirements: tuple[EvidenceRequirement, ...] = ()

    def __post_init__(self) -> None:
        keys = [requirement.key for requirement in self.requirements]
        if len(keys) != len(set(keys)):
            raise ValueError("evidence requirements must have unique keys")

    @property
    def required_keys(self) -> frozenset[str]:
        return frozenset(requirement.key for requirement in self.requirements)

    @property
    def observed_keys(self) -> frozenset[str]:
        return frozenset(item.key for item in self.observations)

    @property
    def missing_keys(self) -> frozenset[str]:
        return self.required_keys - self.observed_keys

    @property
    def confidence_shortfalls(self) -> frozenset[str]:
        shortfalls = {
            requirement.key
            for requirement in self.requirements
            if not any(item.meets_requirement(requirement) for item in self.observations if item.key == requirement.key)
        }
        return frozenset(shortfalls)

    @property
    def has_observation_failures(self) -> bool:
        return any(item.is_observation_failure for item in self.observations)

    @property
    def has_uncertainty(self) -> bool:
        return any(item.is_uncertain for item in self.observations)

    @property
    def has_conflicts(self) -> bool:
        if any(item.polarity is EvidencePolarity.CONFLICTING for item in self.observations):
            return True

        polarities_by_key: dict[str, set[EvidencePolarity]] = {}
        for item in self.observations:
            polarities_by_key.setdefault(item.key, set()).add(item.polarity)
        return any(
            EvidencePolarity.SUPPORTS in polarities
            and EvidencePolarity.CONTRADICTS in polarities
            for polarities in polarities_by_key.values()
        )

    @property
    def is_complete(self) -> bool:
        return bool(self.required_keys) and not self.missing_keys


@dataclass(frozen=True)
class ObservedNode:
    path: str
    kind: NodeKind
    protection: ProtectionClass

    def __post_init__(self) -> None:
        if not self.path.strip():
            raise ValueError("observed node path must not be empty")

    @property
    def is_git_metadata(self) -> bool:
        return self.kind in {NodeKind.GIT_DIRECTORY, NodeKind.GIT_FILE}


@dataclass(frozen=True)
class CleanupCandidate:
    """A node admitted to analysis after explicit candidate-selection evidence."""

    node: ObservedNode
    selection_evidence: EvidenceBundle

    def __post_init__(self) -> None:
        if not self.selection_evidence.observations:
            raise ValueError("cleanup candidate requires selection evidence")
        if self.node.is_git_metadata or self.node.protection is ProtectionClass.REPOSITORY_PROTECTED:
            raise ValueError("Git repository metadata is ObservedNode protection/context, not a CleanupCandidate")
