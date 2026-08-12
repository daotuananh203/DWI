"""Small shared primitives for bounded read-only artifact detectors."""

from __future__ import annotations

import os
import stat
from pathlib import Path
from typing import Iterable, Mapping

from .domain import (
    ActivityState,
    Confidence,
    Evidence,
    EvidencePolarity,
    EvidenceRequirement,
    NodeKind,
    ObservationStatus,
    ProtectionClass,
    ReachabilityState,
)


def make_evidence(
    source: str,
    key: str,
    description: str,
    *,
    status: ObservationStatus,
    polarity: EvidencePolarity,
    confidence: Confidence,
    value: str | None = None,
) -> Evidence:
    return Evidence(
        key=key,
        source=source,
        description=description,
        observation_status=status,
        polarity=polarity,
        confidence=confidence,
        value=value,
    )


def observed_evidence(
    source: str,
    key: str,
    description: str,
    *,
    confidence: Confidence = Confidence.HIGH,
    value: str | None = None,
) -> Evidence:
    return make_evidence(
        source,
        key,
        description,
        status=ObservationStatus.OBSERVED,
        polarity=EvidencePolarity.SUPPORTS,
        confidence=confidence,
        value=value,
    )


def not_observed_evidence(source: str, key: str, description: str) -> Evidence:
    return make_evidence(
        source,
        key,
        description,
        status=ObservationStatus.NOT_OBSERVED,
        polarity=EvidencePolarity.UNKNOWN,
        confidence=Confidence.UNKNOWN,
    )


def confirmed_absent_evidence(source: str, key: str, description: str) -> Evidence:
    return make_evidence(
        source,
        key,
        description,
        status=ObservationStatus.CONFIRMED_ABSENT,
        polarity=EvidencePolarity.CONTRADICTS,
        confidence=Confidence.HIGH,
    )


def unknown_evidence(source: str, key: str, description: str) -> Evidence:
    return make_evidence(
        source,
        key,
        description,
        status=ObservationStatus.UNKNOWN,
        polarity=EvidencePolarity.UNKNOWN,
        confidence=Confidence.UNKNOWN,
    )


def failed_evidence(source: str, key: str, description: str) -> Evidence:
    return make_evidence(
        source,
        key,
        description,
        status=ObservationStatus.FAILED,
        polarity=EvidencePolarity.UNKNOWN,
        confidence=Confidence.UNKNOWN,
    )


def context_unknown_evidence(source: str) -> tuple[Evidence, ...]:
    """Record safety context not inspected by a bounded single-path detector."""

    return (
        unknown_evidence(
            source,
            "reference_check_observation",
            "This bounded detector does not inspect references or consumers.",
        ),
        unknown_evidence(
            source,
            "runtime_activity_observation",
            "This bounded detector does not inspect running processes or runtime activity.",
        ),
        unknown_evidence(
            source,
            "protection_indicator_observation",
            "Protection context is not established by this bounded detector.",
        ),
    )


def activity_from_evidence(observations: Iterable[Evidence]) -> ActivityState:
    """Interpret only the activity dimension from detector-neutral evidence."""

    observations = tuple(observations)
    if key_conflicts(observations, "runtime_activity_observation"):
        return ActivityState.CONFLICTING
    if any(
        item.polarity.value == "supports"
        and item.value == ActivityState.INACTIVE.value
        and not item.is_uncertain
        for item in observations
        if item.key == "runtime_activity_observation"
    ):
        return ActivityState.INACTIVE
    if any(
        item.polarity.value == "supports"
        and item.value == ActivityState.ACTIVE_RUNTIME.value
        and not item.is_uncertain
        for item in observations
        if item.key == "runtime_activity_observation"
    ):
        return ActivityState.ACTIVE_RUNTIME
    return ActivityState.UNKNOWN


def protection_from_evidence(observations: Iterable[Evidence]) -> ProtectionClass:
    """Interpret only the protection dimension from detector-neutral evidence."""

    observations = tuple(observations)
    if key_conflicts(observations, "protection_indicator_observation"):
        return ProtectionClass.CONFLICTING
    for item in observations:
        if item.key != "protection_indicator_observation" or item.polarity.value != "supports" or item.is_uncertain:
            continue
        for protection in ProtectionClass:
            if item.value == protection.value:
                return protection
    return ProtectionClass.UNKNOWN


def observed_node_kind(path: Path) -> NodeKind:
    try:
        metadata = os.lstat(path)
    except (FileNotFoundError, NotADirectoryError):
        return NodeKind.UNKNOWN
    except (PermissionError, OSError):
        return NodeKind.INACCESSIBLE

    if stat.S_ISLNK(metadata.st_mode):
        return NodeKind.SYMLINK
    if stat.S_ISDIR(metadata.st_mode):
        return NodeKind.DIRECTORY
    if stat.S_ISREG(metadata.st_mode):
        return NodeKind.FILE
    return NodeKind.UNKNOWN


def key_conflicts(observations: Iterable[Evidence], key: str) -> bool:
    items = [item for item in observations if item.key == key]
    if any(item.polarity is EvidencePolarity.CONFLICTING for item in items):
        return True
    polarities = {item.polarity for item in items}
    return {
        EvidencePolarity.SUPPORTS,
        EvidencePolarity.CONTRADICTS,
    }.issubset(polarities)


def key_has_uncertainty(observations: Iterable[Evidence], key: str) -> bool:
    return any(
        item.is_uncertain
        for item in observations
        if item.key == key
    )


def positive_evidence_meets(
    observations: Iterable[Evidence],
    key: str,
    requirements: Mapping[str, EvidenceRequirement],
) -> bool:
    return any(
        item.polarity is EvidencePolarity.SUPPORTS
        and item.meets_requirement(requirements[key])
        for item in observations
        if item.key == key
    )


def confirmed_absence_meets(
    observations: Iterable[Evidence],
    key: str,
    requirements: Mapping[str, EvidenceRequirement],
) -> bool:
    return any(
        item.observation_status is ObservationStatus.CONFIRMED_ABSENT
        and item.meets_requirement(requirements[key])
        for item in observations
        if item.key == key
    )


def reachability_from_evidence(
    observations: Iterable[Evidence],
    requirements: Mapping[str, EvidenceRequirement],
) -> ReachabilityState:
    observations = tuple(observations)
    if key_conflicts(observations, "reference_check_observation"):
        return ReachabilityState.CONFLICTING
    if positive_evidence_meets(observations, "reference_check_observation", requirements):
        return ReachabilityState.CONFIRMED_REFERENCED
    if confirmed_absence_meets(observations, "reference_check_observation", requirements):
        return ReachabilityState.CONFIRMED_UNREFERENCED
    return ReachabilityState.UNKNOWN
