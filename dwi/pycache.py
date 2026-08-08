"""Read-only, non-recursive inspection of one Python ``__pycache__`` path.

The detector records filesystem observations only. It does not select cleanup
candidates, assign risk labels, or inspect processes and references. The small
interpreter below derives domain-state evidence from a structurally valid
bytecode observation while preserving unknown safety dimensions.
"""

from __future__ import annotations

import importlib.util
import marshal
import os
from dataclasses import dataclass
from pathlib import Path
from types import CodeType

from .contracts import ArtifactKind, EvidenceAssessment, contract_for, requirements_by_key
from .detector_support import (
    confirmed_absence_meets,
    confirmed_absent_evidence,
    failed_evidence,
    key_conflicts,
    key_has_uncertainty,
    make_evidence,
    not_observed_evidence,
    observed_evidence,
    observed_node_kind as _node_kind,
    positive_evidence_meets,
    reachability_from_evidence,
    unknown_evidence,
)
from .domain import (
    ActivityState,
    Confidence,
    Evidence,
    EvidenceBundle,
    EvidencePolarity,
    EvidenceRequirement,
    NodeKind,
    ObservationStatus,
    ObservedNode,
    ProtectionClass,
    Provenance,
    ReclaimPriority,
    RegenerabilityState,
    RegenerationCost,
    ReachabilityState,
)


_PYTHON_BYTECODE_HEADER_SIZE = 16
_PYTHON_BYTECODE_MAGIC = importlib.util.MAGIC_NUMBER
_DETECTOR_SOURCE = "pycache-detector"


@dataclass(frozen=True)
class PycacheDetection:
    """Raw observations for one inspected path; no interpreted domain states."""

    node: ObservedNode
    observations: tuple[Evidence, ...]

    def contract_assessment(self) -> EvidenceAssessment:
        return contract_for(ArtifactKind.PYCACHE).assess(self.observations)

    @property
    def evidence(self) -> EvidenceBundle:
        return self.contract_assessment().bundle


@dataclass(frozen=True)
class PycacheInterpretation:
    """Domain-state interpretation without a RiskLabel or action decision."""

    provenance: Provenance | None
    regenerability: RegenerabilityState
    regeneration_cost: RegenerationCost
    reachability: ReachabilityState
    activity: ActivityState
    protection: ProtectionClass
    reclaim_priority: ReclaimPriority = ReclaimPriority.UNKNOWN


def _evidence(
    key: str,
    description: str,
    *,
    status: ObservationStatus,
    polarity: EvidencePolarity,
    confidence: Confidence,
    value: str | None = None,
) -> Evidence:
    return make_evidence(
        _DETECTOR_SOURCE,
        key,
        description,
        status=status,
        polarity=polarity,
        confidence=confidence,
        value=value,
    )


def _observed(key: str, description: str, *, confidence: Confidence = Confidence.HIGH, value: str | None = None) -> Evidence:
    return observed_evidence(
        _DETECTOR_SOURCE,
        key,
        description,
        confidence=confidence,
        value=value,
    )


def _not_observed(key: str, description: str) -> Evidence:
    return not_observed_evidence(_DETECTOR_SOURCE, key, description)


def _confirmed_absent(key: str, description: str) -> Evidence:
    return confirmed_absent_evidence(_DETECTOR_SOURCE, key, description)


def _unknown(key: str, description: str) -> Evidence:
    return unknown_evidence(_DETECTOR_SOURCE, key, description)


def _failed(key: str, description: str) -> Evidence:
    return failed_evidence(_DETECTOR_SOURCE, key, description)


def _read_pyc(data: bytes) -> tuple[str | None, str]:
    """Return an embedded source filename and a raw validation outcome."""

    if len(data) < 4 or data[:4] != _PYTHON_BYTECODE_MAGIC:
        return None, "weak"
    if len(data) < _PYTHON_BYTECODE_HEADER_SIZE:
        return None, "weak"

    try:
        code = marshal.loads(data[_PYTHON_BYTECODE_HEADER_SIZE:])
    except Exception:
        return None, "failed"
    if not isinstance(code, CodeType):
        return None, "failed"
    source_name = code.co_filename.strip() or None
    return source_name, "valid"


def _context_unknown_evidence() -> tuple[Evidence, ...]:
    return (
        _unknown(
            "reference_check_observation",
            "This single-directory detector does not inspect references or consumers.",
        ),
        _unknown(
            "runtime_activity_observation",
            "This detector does not inspect running processes or runtime activity.",
        ),
        _unknown(
            "protection_indicator_observation",
            "Protection context is not established by this detector.",
        ),
    )


def _name_observation(path: Path) -> Evidence:
    if path.name == "__pycache__":
        return _observed(
            "pycache_directory_name_observation",
            "The inspected path has the exact Python __pycache__ directory name.",
            value=path.name,
        )
    return _confirmed_absent(
        "pycache_directory_name_observation",
        "The inspected path does not have the exact Python __pycache__ directory name.",
    )


def _uninspectable(path: Path, node_kind: NodeKind) -> PycacheDetection:
    if node_kind is NodeKind.UNKNOWN:
        path_observation = _not_observed(
            "path_object_observation",
            "The inspected path was not observed.",
        )
        metadata_observation = _failed(
            "metadata_readability_observation",
            "Directory metadata could not be read because the path was not observed.",
        )
    elif node_kind is NodeKind.INACCESSIBLE:
        path_observation = _evidence(
            "path_object_observation",
            "The inspected path could not be read reliably.",
            status=ObservationStatus.INACCESSIBLE,
            polarity=EvidencePolarity.UNKNOWN,
            confidence=Confidence.UNKNOWN,
        )
        metadata_observation = _failed(
            "metadata_readability_observation",
            "Directory metadata could not be read.",
        )
    else:
        path_observation = _observed(
            "path_object_observation",
            f"The inspected path is a {node_kind.value}, not a directory.",
            value=node_kind.value,
        )
        metadata_observation = _failed(
            "metadata_readability_observation",
            "Direct directory entries could not be read because the path is not a directory.",
        )

    return PycacheDetection(
        node=ObservedNode(
            path=str(path),
            kind=node_kind,
            protection=ProtectionClass.UNKNOWN,
        ),
        observations=(
            _name_observation(path),
            path_observation,
            metadata_observation,
            _not_observed(
                "generator_indicator_observation",
                "Python bytecode markers could not be inspected.",
            ),
            _not_observed(
                "recreation_input_availability_observation",
                "Recreation-input observations could not be inspected.",
            ),
            _not_observed(
                "python_bytecode_marker",
                "No Python bytecode marker was observed because inspection did not complete.",
            ),
            _not_observed(
                "python_source_reference_observation",
                "Embedded source references could not be inspected.",
            ),
            *_context_unknown_evidence(),
        ),
    )


def inspect_pycache(path: str | os.PathLike[str]) -> PycacheDetection:
    """Inspect one path and its direct children without recursion or mutation."""

    inspected_path = Path(path)
    node_kind = _node_kind(inspected_path)
    if node_kind is not NodeKind.DIRECTORY:
        return _uninspectable(inspected_path, node_kind)

    observations: list[Evidence] = [
        _name_observation(inspected_path),
        _observed(
            "path_object_observation",
            "The inspected path is a directory.",
            value=NodeKind.DIRECTORY.value,
        ),
    ]

    marker_observations: list[Evidence] = []
    source_observations: list[Evidence] = []
    availability_observations: list[Evidence] = []
    bytecode_entries = 0
    valid_bytecode_found = False
    directory_read_succeeded = False
    inspection_failed = False

    try:
        with os.scandir(inspected_path) as entries:
            direct_entries = sorted(entries, key=lambda entry: entry.name)
            directory_read_succeeded = True
            for entry in direct_entries:
                if not entry.name.endswith(".pyc"):
                    continue
                bytecode_entries += 1
                try:
                    if entry.is_symlink():
                        raise OSError("symlinked bytecode entry was not followed")
                    if not entry.is_file(follow_symlinks=False):
                        raise OSError("bytecode entry is not a regular file")
                    source_name, outcome = _read_pyc(Path(entry.path).read_bytes())
                except (PermissionError, OSError) as error:
                    inspection_failed = True
                    marker_observations.append(
                        _failed(
                            "python_bytecode_marker",
                            f"Could not inspect direct bytecode entry {entry.name}: {error}.",
                        )
                    )
                    continue

                if outcome == "valid":
                    valid_bytecode_found = True
                    marker_observations.append(
                        _observed(
                            "python_bytecode_marker",
                            f"A valid Python bytecode header and code object were observed in {entry.name}.",
                            value=entry.name,
                        )
                    )
                    if source_name is None:
                        source_observations.append(
                            _confirmed_absent(
                                "python_source_reference_observation",
                                f"No embedded source filename was present in {entry.name}.",
                            )
                        )
                        availability_observations.append(
                            _unknown(
                                "recreation_input_availability_observation",
                                f"Recreation-input availability was not checked for {entry.name}.",
                            )
                        )
                    else:
                        source_observations.append(
                            _observed(
                                "python_source_reference_observation",
                                f"An embedded source filename reference was observed in {entry.name}; the source file was not read.",
                                value=source_name,
                            )
                        )
                        availability_observations.append(
                            _unknown(
                                "recreation_input_availability_observation",
                                f"The embedded source reference in {entry.name} does not establish recreation-input availability.",
                            )
                        )
                elif outcome == "weak":
                    marker_observations.append(
                        _observed(
                            "python_bytecode_marker",
                            f"Only a weak bytecode-like signal was observed in {entry.name}; the Python bytecode could not be validated.",
                            confidence=Confidence.LOW,
                            value=entry.name,
                        )
                    )
                else:
                    inspection_failed = True
                    marker_observations.append(
                        _failed(
                            "python_bytecode_marker",
                            f"The bytecode payload in {entry.name} could not be parsed.",
                        )
                    )
    except (PermissionError, OSError):
        inspection_failed = True

    if inspection_failed and not marker_observations:
        marker_observations.append(
            _failed(
                "python_bytecode_marker",
                "Direct directory entries could not be inspected completely.",
            )
        )
    elif not marker_observations:
        marker_observations.append(
            _confirmed_absent(
                "python_bytecode_marker",
                "The readable directory contained no direct .pyc entry.",
            )
        )
    if not source_observations:
        source_observations.append(
            _not_observed(
                "python_source_reference_observation",
                "No valid bytecode source reference was observed.",
            )
        )
    if not availability_observations:
        availability_observations.append(
            _not_observed(
                "recreation_input_availability_observation",
                "No recreation-input reference was observed.",
            )
        )

    if valid_bytecode_found:
        generator_observation = _observed(
            "generator_indicator_observation",
            "A direct entry contains the current Python bytecode magic and a readable code object.",
            value="python-bytecode",
        )
    elif bytecode_entries:
        generator_observation = _observed(
            "generator_indicator_observation",
            "A direct .pyc entry was observed, but Python bytecode validation was insufficient.",
            confidence=Confidence.LOW,
            value="pyc-extension-only",
        )
    elif directory_read_succeeded:
        generator_observation = _confirmed_absent(
            "generator_indicator_observation",
            "No direct Python bytecode marker was observed.",
        )
    else:
        generator_observation = _failed(
            "generator_indicator_observation",
            "The directory could not be read to inspect Python bytecode markers.",
        )

    if directory_read_succeeded:
        metadata_observation = _observed(
            "metadata_readability_observation",
            "The directory and its direct entries were readable.",
        )
    else:
        metadata_observation = _failed(
            "metadata_readability_observation",
            "The directory's direct entries could not be read.",
        )

    observations.extend(
        (
            metadata_observation,
            generator_observation,
            *availability_observations,
            *marker_observations,
            *source_observations,
            *_context_unknown_evidence(),
        )
    )

    return PycacheDetection(
        node=ObservedNode(
            path=str(inspected_path),
            kind=NodeKind.DIRECTORY,
            protection=ProtectionClass.UNKNOWN,
        ),
        observations=tuple(observations),
    )


def _meets(
    detection: PycacheDetection,
    key: str,
    requirements: dict[str, EvidenceRequirement],
) -> bool:
    return positive_evidence_meets(detection.observations, key, requirements)


def _key_conflicts(detection: PycacheDetection, key: str) -> bool:
    return key_conflicts(detection.observations, key)


def _key_has_uncertainty(detection: PycacheDetection, key: str) -> bool:
    return key_has_uncertainty(detection.observations, key)


def interpret_pycache(detection: PycacheDetection) -> PycacheInterpretation:
    """Interpret structural pycache evidence into separate domain dimensions."""

    requirements = requirements_by_key(ArtifactKind.PYCACHE)
    name_valid = _meets(detection, "pycache_directory_name_observation", requirements)
    marker_valid = _meets(detection, "python_bytecode_marker", requirements)
    source_valid = _meets(detection, "python_source_reference_observation", requirements)

    structural_conflict = any(
        _key_conflicts(detection, key)
        for key in (
            "pycache_directory_name_observation",
            "python_bytecode_marker",
            "python_source_reference_observation",
        )
    )
    structural_uncertainty = any(
        _key_has_uncertainty(detection, key)
        for key in (
            "pycache_directory_name_observation",
            "python_bytecode_marker",
            "python_source_reference_observation",
        )
    )

    availability_conflict = _key_conflicts(
        detection,
        "recreation_input_availability_observation",
    )
    availability_confirmed_absent = confirmed_absence_meets(
        detection.observations,
        "recreation_input_availability_observation",
        requirements,
    )
    provenance = (
        Provenance(
            ecosystem="python",
            generator="python-bytecode",
            confidence=Confidence.HIGH,
            evidence_keys=(
                "pycache_directory_name_observation",
                "python_bytecode_marker",
            ),
        )
        if name_valid and marker_valid and not structural_conflict and not structural_uncertainty
        else None
    )

    if structural_conflict or availability_conflict:
        regenerability = RegenerabilityState.CONFLICTING
        regeneration_cost = RegenerationCost.UNKNOWN
    elif structural_uncertainty or availability_confirmed_absent:
        regenerability = RegenerabilityState.UNKNOWN
        regeneration_cost = RegenerationCost.UNKNOWN
    elif name_valid and marker_valid and source_valid:
        regenerability = RegenerabilityState.CONDITIONALLY_REPRODUCIBLE
        regeneration_cost = RegenerationCost.LOW
    else:
        regenerability = RegenerabilityState.UNKNOWN
        regeneration_cost = RegenerationCost.UNKNOWN

    reachability = reachability_from_evidence(detection.observations, requirements)

    activity = (
        ActivityState.CONFLICTING
        if _key_conflicts(detection, "runtime_activity_observation")
        else ActivityState.UNKNOWN
    )
    protection = (
        ProtectionClass.CONFLICTING
        if _key_conflicts(detection, "protection_indicator_observation")
        else ProtectionClass.UNKNOWN
    )

    return PycacheInterpretation(
        provenance=provenance,
        regenerability=regenerability,
        regeneration_cost=regeneration_cost,
        reachability=reachability,
        activity=activity,
        protection=protection,
    )
