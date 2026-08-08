"""Small shared primitives for bounded read-only artifact detectors."""

from __future__ import annotations

import os
import stat
from pathlib import Path
from typing import Iterable, Mapping

from .domain import (
    Confidence,
    Evidence,
    EvidencePolarity,
    EvidenceRequirement,
    NodeKind,
    ObservationStatus,
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
