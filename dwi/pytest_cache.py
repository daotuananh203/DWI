"""Read-only, single-path inspection of a pytest ``.pytest_cache`` directory."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from .contracts import ArtifactKind, EvidenceAssessment, contract_for, requirements_by_key
from .detector_support import (
    activity_from_evidence,
    confirmed_absent_evidence,
    failed_evidence,
    key_conflicts,
    key_has_uncertainty,
    not_observed_evidence,
    observed_evidence,
    observed_node_kind,
    positive_evidence_meets,
    protection_from_evidence,
    reachability_from_evidence,
    unknown_evidence,
)
from .domain import (
    ActivityState,
    Confidence,
    Evidence,
    EvidenceBundle,
    NodeKind,
    ObservedNode,
    ProtectionClass,
    Provenance,
    ReclaimPriority,
    RegenerabilityState,
    RegenerationCost,
    ReachabilityState,
)


_DETECTOR_SOURCE = "pytest-cache-detector"
_CACHEDIR_TAG_SIGNATURE = "Signature: 8a477f597d28d172789f06886806bc55"


@dataclass(frozen=True)
class PytestCacheDetection:
    """Raw observations for one inspected path; no domain interpretation."""

    node: ObservedNode
    observations: tuple[Evidence, ...]

    def contract_assessment(self) -> EvidenceAssessment:
        return contract_for(ArtifactKind.PYTEST_CACHE).assess(self.observations)

    @property
    def evidence(self) -> EvidenceBundle:
        return self.contract_assessment().bundle


@dataclass(frozen=True)
class PytestCacheInterpretation:
    """Domain-state interpretation without a RiskLabel or action decision."""

    provenance: Provenance | None
    regenerability: RegenerabilityState
    regeneration_cost: RegenerationCost
    reachability: ReachabilityState
    activity: ActivityState
    protection: ProtectionClass
    reclaim_priority: ReclaimPriority = ReclaimPriority.UNKNOWN


def _observed(
    key: str,
    description: str,
    *,
    confidence: Confidence = Confidence.HIGH,
    value: str | None = None,
) -> Evidence:
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


def _name_observation(path: Path) -> Evidence:
    if path.name == ".pytest_cache":
        return _observed(
            "pytest_cache_directory_name_observation",
            "The inspected path has the exact pytest .pytest_cache directory name.",
            value=path.name,
        )
    return _confirmed_absent(
        "pytest_cache_directory_name_observation",
        "The inspected path does not have the exact pytest .pytest_cache directory name.",
    )


def _uninspectable(path: Path, node_kind: NodeKind) -> PytestCacheDetection:
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
        path_observation = _unknown(
            "path_object_observation",
            "The inspected path could not be read reliably.",
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

    return PytestCacheDetection(
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
                "Pytest cache markers could not be inspected.",
            ),
            _not_observed(
                "recreation_input_availability_observation",
                "Recreation-input availability was not inspected.",
            ),
            _not_observed(
                "pytest_cache_marker",
                "Pytest cache markers could not be inspected.",
            ),
            _not_observed(
                "cache_layout_observation",
                "Pytest cache layout could not be inspected.",
            ),
            _unknown(
                "reference_check_observation",
                "This detector does not inspect references or consumers.",
            ),
            _unknown(
                "runtime_activity_observation",
                "This detector does not inspect running processes or runtime activity.",
            ),
            _unknown(
                "protection_indicator_observation",
                "Protection context is not established by this detector.",
            ),
        ),
    )


def _read_marker(path: Path, marker_name: str) -> tuple[Evidence, bool, bool]:
    """Return marker evidence, whether it is valid, and whether it is weak."""

    try:
        if path.is_symlink() or not path.is_file():
            raise OSError("marker is not a regular file")
        content = path.read_text(encoding="utf-8", errors="replace")
    except (PermissionError, OSError) as error:
        return (
            _failed(
                "pytest_cache_marker",
                f"Could not inspect {marker_name}: {error}.",
            ),
            False,
            False,
        )

    if marker_name == "CACHEDIR.TAG":
        first_line = content.splitlines()[0].strip() if content.splitlines() else ""
        if first_line == _CACHEDIR_TAG_SIGNATURE:
            return (
                _observed(
                    "pytest_cache_marker",
                    "The standard CACHEDIR.TAG signature was observed.",
                    value=marker_name,
                ),
                True,
                False,
            )
        if content.strip():
            return (
                _observed(
                    "pytest_cache_marker",
                    "A non-empty CACHEDIR.TAG was observed without the standard signature.",
                    confidence=Confidence.LOW,
                    value=marker_name,
                ),
                False,
                True,
            )
        return (
            _failed(
                "pytest_cache_marker",
                "CACHEDIR.TAG was present but empty.",
            ),
            False,
            False,
        )

    normalized = content.casefold()
    if content.strip() and "pytest" in normalized and "cache" in normalized:
        return (
            _observed(
                "pytest_cache_marker",
                "README.md contains recognizable pytest cache wording.",
                value=marker_name,
            ),
            True,
            False,
        )
    if content.strip():
        return (
            _observed(
                "pytest_cache_marker",
                "A non-empty README.md was observed without recognizable pytest cache wording.",
                confidence=Confidence.LOW,
                value=marker_name,
            ),
            False,
            True,
        )
    return (
        _failed(
            "pytest_cache_marker",
            "README.md was present but empty.",
        ),
        False,
        False,
    )


def inspect_pytest_cache(
    path: str | os.PathLike[str],
    *,
    disposable_root: bool = False,
) -> PytestCacheDetection:
    """Inspect one path and its direct children without recursion or mutation."""

    inspected_path = Path(path)
    node_kind = observed_node_kind(inspected_path)
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
    layout_observations: list[Evidence] = []
    valid_marker_found = False
    weak_marker_found = False
    inspection_failed = False
    directory_read_succeeded = False

    try:
        with os.scandir(inspected_path) as entries:
            direct_entries = sorted(entries, key=lambda entry: entry.name)
            directory_read_succeeded = True
            for entry in direct_entries:
                if entry.name in {"CACHEDIR.TAG", "README.md"}:
                    marker_evidence, valid, weak = _read_marker(
                        Path(entry.path),
                        entry.name,
                    )
                    marker_observations.append(marker_evidence)
                    valid_marker_found = valid_marker_found or valid
                    weak_marker_found = weak_marker_found or weak
                elif entry.name == "v":
                    entry_kind = observed_node_kind(Path(entry.path))
                    if entry_kind is NodeKind.DIRECTORY:
                        layout_observations.append(
                            _observed(
                                "cache_layout_observation",
                                "A direct v directory was observed in the pytest cache path.",
                                value="v",
                            )
                        )
                    else:
                        inspection_failed = True
                        layout_observations.append(
                            _failed(
                                "cache_layout_observation",
                                "The pytest cache v entry was not a readable directory.",
                            )
                        )
    except (PermissionError, OSError):
        inspection_failed = True

    if not marker_observations:
        if directory_read_succeeded:
            marker_observations.append(
                _confirmed_absent(
                    "pytest_cache_marker",
                    "No direct CACHEDIR.TAG or README.md marker was observed.",
                )
            )
        else:
            marker_observations.append(
                _failed(
                    "pytest_cache_marker",
                    "The directory could not be read to inspect pytest cache markers.",
                )
            )

    if not layout_observations:
        if valid_marker_found:
            layout_observations.append(
                _observed(
                    "cache_layout_observation",
                    "A recognized pytest cache marker was observed at the direct cache root.",
                    value="root-marker",
                )
            )
        elif weak_marker_found:
            layout_observations.append(
                _observed(
                    "cache_layout_observation",
                    "Only a weak pytest cache marker was observed at the direct cache root.",
                    confidence=Confidence.LOW,
                    value="root-marker-weak",
                )
            )
        elif directory_read_succeeded:
            layout_observations.append(
                _confirmed_absent(
                    "cache_layout_observation",
                    "No recognized direct pytest cache layout evidence was observed.",
                )
            )
        else:
            layout_observations.append(
                _failed(
                    "cache_layout_observation",
                    "The directory could not be read to inspect pytest cache layout.",
                )
            )

    if valid_marker_found:
        generator_observation = _observed(
            "generator_indicator_observation",
            "A recognized pytest cache marker was observed.",
            value="pytest-cache-marker",
        )
    elif weak_marker_found:
        generator_observation = _observed(
            "generator_indicator_observation",
            "A direct pytest-cache-like marker was observed with weak confidence.",
            confidence=Confidence.LOW,
            value="pytest-cache-marker-weak",
        )
    elif inspection_failed or not directory_read_succeeded:
        generator_observation = _failed(
            "generator_indicator_observation",
            "Pytest cache markers could not be inspected reliably.",
        )
    else:
        generator_observation = _confirmed_absent(
            "generator_indicator_observation",
            "No recognized pytest cache marker was observed.",
        )

    metadata_observation = (
        _observed(
            "metadata_readability_observation",
            "The directory and its direct entries were readable.",
        )
        if directory_read_succeeded
        else _failed(
            "metadata_readability_observation",
            "The directory's direct entries could not be read.",
        )
    )

    observations.extend(
        (
            metadata_observation,
            generator_observation,
            _unknown(
                "recreation_input_availability_observation",
                "This detector does not inspect project inputs or test dependencies.",
            ),
            *marker_observations,
            *layout_observations,
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
    )

    if disposable_root:
        # The scanner has already verified the exact disposable-root marker.
        # Replace unknown context observations with explicit, bounded evidence;
        # absence of a marker remains unknown and therefore fail-closed.
        context_keys = {
            "recreation_input_availability_observation",
            "reference_check_observation",
            "runtime_activity_observation",
            "protection_indicator_observation",
        }
        observations = [item for item in observations if item.key not in context_keys]
        observations.extend((
            _observed(
                "disposable_root_marker_observation",
                "The approved root contains the exact DWI disposable-root marker.",
                value="DWI-DISPOSABLE-ROOT-v0.3",
            ),
            _observed(
                "recreation_input_availability_observation",
                "The explicitly marked disposable scope permits regeneration of this cache family.",
                value="disposable-scope",
            ),
            _confirmed_absent(
                "reference_check_observation",
                "The explicitly marked disposable scope establishes no retained consumer for this bounded fixture.",
            ),
            _observed(
                "runtime_activity_observation",
                "The explicitly marked disposable scope is inactive for this bounded fixture.",
                value=ActivityState.INACTIVE.value,
            ),
            _observed(
                "protection_indicator_observation",
                "The bounded fixture is an ordinary, non-reparse disposable directory.",
                value=ProtectionClass.ORDINARY.value,
            ),
        ))

    return PytestCacheDetection(
        node=ObservedNode(
            path=str(inspected_path),
            kind=NodeKind.DIRECTORY,
            protection=ProtectionClass.ORDINARY if disposable_root else ProtectionClass.UNKNOWN,
        ),
        observations=tuple(observations),
    )


def interpret_pytest_cache(detection: PytestCacheDetection) -> PytestCacheInterpretation:
    """Interpret structural pytest-cache evidence into separate domain dimensions."""

    requirements = requirements_by_key(ArtifactKind.PYTEST_CACHE)
    observations = detection.observations
    name_valid = positive_evidence_meets(
        observations,
        "pytest_cache_directory_name_observation",
        requirements,
    )
    marker_valid = positive_evidence_meets(
        observations,
        "pytest_cache_marker",
        requirements,
    )
    layout_valid = positive_evidence_meets(
        observations,
        "cache_layout_observation",
        requirements,
    )
    structural_keys = (
        "pytest_cache_directory_name_observation",
        "pytest_cache_marker",
        "cache_layout_observation",
    )
    structural_conflict = any(key_conflicts(observations, key) for key in structural_keys)
    structural_uncertainty = any(
        key_has_uncertainty(observations, key)
        for key in structural_keys
    )
    provenance = (
        Provenance(
            ecosystem="python",
            generator="pytest",
            confidence=Confidence.HIGH,
            evidence_keys=structural_keys,
        )
        if name_valid and marker_valid and layout_valid
        and not structural_conflict
        and not structural_uncertainty
        else None
    )

    if structural_conflict:
        regenerability = RegenerabilityState.CONFLICTING
        regeneration_cost = RegenerationCost.UNKNOWN
    elif structural_uncertainty:
        regenerability = RegenerabilityState.UNKNOWN
        regeneration_cost = RegenerationCost.UNKNOWN
    elif name_valid and marker_valid and layout_valid:
        regenerability = RegenerabilityState.CONDITIONALLY_REPRODUCIBLE
        regeneration_cost = RegenerationCost.LOW
    else:
        regenerability = RegenerabilityState.UNKNOWN
        regeneration_cost = RegenerationCost.UNKNOWN

    return PytestCacheInterpretation(
        provenance=provenance,
        regenerability=regenerability,
        regeneration_cost=regeneration_cost,
        reachability=reachability_from_evidence(observations, requirements),
        activity=activity_from_evidence(observations),
        protection=protection_from_evidence(observations),
    )
