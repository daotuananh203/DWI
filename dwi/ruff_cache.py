"""Read-only, bounded inspection of one Ruff ``.ruff_cache`` path.

The detector records raw filesystem observations only. It does not traverse a
workspace, select cleanup candidates, assign risk labels, or inspect runtime
references. The interpreter maps sufficiently strong structural observations
to separate domain dimensions while preserving unknown safety context.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path

from .contracts import ArtifactKind, EvidenceAssessment, contract_for, requirements_by_key
from .detector_support import (
    confirmed_absent_evidence,
    failed_evidence,
    key_conflicts,
    key_has_uncertainty,
    not_observed_evidence,
    observed_evidence,
    observed_node_kind,
    positive_evidence_meets,
    reachability_from_evidence,
    unknown_evidence,
)
from .domain import (
    ActivityState,
    Confidence,
    Evidence,
    EvidenceBundle,
    EvidenceRequirement,
    NodeKind,
    ObservedNode,
    ProtectionClass,
    Provenance,
    ReclaimPriority,
    RegenerabilityState,
    RegenerationCost,
    ReachabilityState,
)


_DETECTOR_SOURCE = "ruff-cache-detector"
_CACHEDIR_TAG_SIGNATURE = "Signature: 8a477f597d28d172789f06886806bc55"
_RUFF_GITIGNORE = "# Automatically created by ruff.\n*\n"
_RUFF_VERSION_DIRECTORY = re.compile(r"^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$")
_CACHE_KEY_FILE = re.compile(r"^\d+$")


@dataclass(frozen=True)
class RuffCacheDetection:
    """Raw observations for one inspected path; no interpreted domain states."""

    node: ObservedNode
    observations: tuple[Evidence, ...]

    def contract_assessment(self) -> EvidenceAssessment:
        return contract_for(ArtifactKind.RUFF_CACHE).assess(self.observations)

    @property
    def evidence(self) -> EvidenceBundle:
        return self.contract_assessment().bundle


@dataclass(frozen=True)
class RuffCacheInterpretation:
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
    if path.name == ".ruff_cache":
        return _observed(
            "ruff_cache_directory_name_observation",
            "The inspected path has the exact Ruff .ruff_cache directory name.",
            value=path.name,
        )
    return _confirmed_absent(
        "ruff_cache_directory_name_observation",
        "The inspected path does not have the exact Ruff .ruff_cache directory name.",
    )


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


def _uninspectable(path: Path, node_kind: NodeKind) -> RuffCacheDetection:
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

    return RuffCacheDetection(
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
                "Ruff cache structure could not be inspected.",
            ),
            _not_observed(
                "recreation_input_availability_observation",
                "Recreation-input availability was not inspected.",
            ),
            _not_observed(
                "ruff_cache_marker",
                "Ruff cache root markers could not be inspected.",
            ),
            _not_observed(
                "cache_layout_observation",
                "Ruff cache version/layout evidence could not be inspected.",
            ),
            *_context_unknown_evidence(),
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
                "ruff_cache_marker",
                f"Could not inspect Ruff cache marker {marker_name}: {error}.",
            ),
            False,
            False,
        )

    normalized = content.replace("\r\n", "\n").replace("\r", "\n")
    if marker_name == "CACHEDIR.TAG":
        first_line = normalized.splitlines()[0].strip() if normalized.splitlines() else ""
        if first_line == _CACHEDIR_TAG_SIGNATURE:
            return (
                _observed(
                    "ruff_cache_marker",
                    "The standard CACHEDIR.TAG signature was observed at the Ruff cache root.",
                    value=marker_name,
                ),
                True,
                False,
            )
    elif normalized == _RUFF_GITIGNORE:
        return (
            _observed(
                "ruff_cache_marker",
                "The Ruff-generated root .gitignore content was observed.",
                value=marker_name,
            ),
            True,
            False,
        )

    if normalized.strip():
        return (
            _observed(
                "ruff_cache_marker",
                f"A non-empty {marker_name} was observed without its supported Ruff marker content.",
                confidence=Confidence.LOW,
                value=marker_name,
            ),
            False,
            True,
        )
    return (
        _failed(
            "ruff_cache_marker",
            f"{marker_name} was present but empty.",
        ),
        False,
        False,
    )


def _version_cache_files(version_path: Path) -> tuple[bool, bool]:
    """Return whether a version directory has valid or weak file evidence."""

    valid_file = False
    weak_file = False
    try:
        with os.scandir(version_path) as entries:
            direct_entries = sorted(entries, key=lambda entry: entry.name)
            for entry in direct_entries:
                if not _CACHE_KEY_FILE.fullmatch(entry.name):
                    continue
                entry_path = Path(entry.path)
                try:
                    if entry_path.is_symlink() or not entry_path.is_file():
                        weak_file = True
                        continue
                    if entry_path.stat().st_size > 0:
                        valid_file = True
                    else:
                        weak_file = True
                except (PermissionError, OSError):
                    weak_file = True
    except (PermissionError, OSError):
        weak_file = True
    return valid_file, weak_file


def inspect_ruff_cache(path: str | os.PathLike[str]) -> RuffCacheDetection:
    """Inspect one path and its direct Ruff cache layout without mutation."""

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
    marker_valid: set[str] = set()
    inspection_failed = False
    directory_read_succeeded = False
    version_observations: list[tuple[Path, bool, bool]] = []

    try:
        with os.scandir(inspected_path) as entries:
            direct_entries = sorted(entries, key=lambda entry: entry.name)
            directory_read_succeeded = True
            for entry in direct_entries:
                entry_path = Path(entry.path)
                if entry.name in {"CACHEDIR.TAG", ".gitignore"}:
                    marker_evidence, valid, _ = _read_marker(entry_path, entry.name)
                    marker_observations.append(marker_evidence)
                    if valid:
                        marker_valid.add(entry.name)
                elif _RUFF_VERSION_DIRECTORY.fullmatch(entry.name):
                    try:
                        if entry_path.is_dir() and not entry_path.is_symlink():
                            valid_file, weak_file = _version_cache_files(entry_path)
                            version_observations.append((entry_path, valid_file, weak_file))
                            inspection_failed = inspection_failed or weak_file
                        else:
                            inspection_failed = True
                            version_observations.append((entry_path, False, True))
                    except (PermissionError, OSError):
                        inspection_failed = True
                        version_observations.append((entry_path, False, True))
    except (PermissionError, OSError):
        inspection_failed = True

    if not marker_observations:
        if directory_read_succeeded:
            marker_observations.append(
                _confirmed_absent(
                    "ruff_cache_marker",
                    "No direct CACHEDIR.TAG or Ruff-generated .gitignore marker was observed.",
                )
            )
        else:
            marker_observations.append(
                _failed(
                    "ruff_cache_marker",
                    "The directory could not be read to inspect Ruff cache root markers.",
                )
            )

    valid_layout = any(valid_file for _, valid_file, _ in version_observations)
    weak_layout = any(weak_file for _, _, weak_file in version_observations)
    if valid_layout:
        version_name = next(
            version_path.name
            for version_path, valid_file, _ in version_observations
            if valid_file
        )
        layout_observation = _observed(
            "cache_layout_observation",
            "A Ruff version directory with a non-empty decimal cache-key file was observed.",
            value=version_name,
        )
    elif weak_layout or version_observations:
        layout_observation = _observed(
            "cache_layout_observation",
            "A Ruff version directory was observed without validated cache-key file evidence.",
            confidence=Confidence.LOW,
            value="version-directory-only",
        )
    elif directory_read_succeeded:
        layout_observation = _confirmed_absent(
            "cache_layout_observation",
            "No Ruff version directory was observed at the cache root.",
        )
    else:
        layout_observation = _failed(
            "cache_layout_observation",
            "The directory could not be read to inspect Ruff cache layout.",
        )

    observations.extend(
        (
            _observed(
                "metadata_readability_observation",
                "The Ruff cache root and direct version layout were readable.",
            )
            if directory_read_succeeded and not inspection_failed
            else _failed(
                "metadata_readability_observation",
                "The Ruff cache root or direct version layout could not be read reliably.",
            ),
            _observed(
                "generator_indicator_observation",
                "Both supported Ruff root markers and versioned cache-key structure were observed.",
                value="ruff-cache-structure",
            )
            if marker_valid == {"CACHEDIR.TAG", ".gitignore"} and valid_layout
            else _observed(
                "generator_indicator_observation",
                "Only partial Ruff cache marker or layout evidence was observed.",
                confidence=Confidence.LOW,
                value="ruff-cache-partial-structure",
            )
            if marker_observations and not inspection_failed
            else _failed(
                "generator_indicator_observation",
                "Ruff cache structure could not be inspected reliably.",
            ),
            _unknown(
                "recreation_input_availability_observation",
                "This detector does not inspect source inputs or Ruff configuration.",
            ),
            *marker_observations,
            layout_observation,
            *_context_unknown_evidence(),
        )
    )

    return RuffCacheDetection(
        node=ObservedNode(
            path=str(inspected_path),
            kind=NodeKind.DIRECTORY,
            protection=ProtectionClass.UNKNOWN,
        ),
        observations=tuple(observations),
    )


def _has_weak_evidence(
    observations: tuple[Evidence, ...],
    key: str,
    requirement: EvidenceRequirement,
) -> bool:
    return any(
        item.key == key
        and item.confidence.rank < requirement.minimum_confidence.rank
        for item in observations
    )


def interpret_ruff_cache(detection: RuffCacheDetection) -> RuffCacheInterpretation:
    """Interpret structural Ruff evidence into separate domain dimensions."""

    requirements = requirements_by_key(ArtifactKind.RUFF_CACHE)
    observations = detection.observations
    structural_keys = (
        "ruff_cache_directory_name_observation",
        "ruff_cache_marker",
        "cache_layout_observation",
    )
    marker_values = {
        item.value
        for item in observations
        if item.key == "ruff_cache_marker"
        and item.polarity.value == "supports"
        and item.value in {"CACHEDIR.TAG", ".gitignore"}
        and item.meets_requirement(requirements["ruff_cache_marker"])
    }
    structural_valid = (
        positive_evidence_meets(
            observations,
            "ruff_cache_directory_name_observation",
            requirements,
        )
        and marker_values == {"CACHEDIR.TAG", ".gitignore"}
        and positive_evidence_meets(
            observations,
            "cache_layout_observation",
            requirements,
        )
    )
    structural_conflict = any(key_conflicts(observations, key) for key in structural_keys)
    structural_uncertainty = any(
        key_has_uncertainty(observations, key)
        or _has_weak_evidence(observations, key, requirements[key])
        for key in structural_keys
    )
    provenance = (
        Provenance(
            ecosystem="python",
            generator="ruff",
            confidence=Confidence.HIGH,
            evidence_keys=structural_keys,
        )
        if structural_valid and not structural_conflict and not structural_uncertainty
        else None
    )

    if structural_conflict:
        regenerability = RegenerabilityState.CONFLICTING
    elif structural_uncertainty:
        regenerability = RegenerabilityState.UNKNOWN
    elif structural_valid:
        regenerability = RegenerabilityState.CONDITIONALLY_REPRODUCIBLE
    else:
        regenerability = RegenerabilityState.UNKNOWN

    return RuffCacheInterpretation(
        provenance=provenance,
        regenerability=regenerability,
        regeneration_cost=RegenerationCost.LOW,
        reachability=reachability_from_evidence(observations, requirements),
        activity=(
            ActivityState.CONFLICTING
            if key_conflicts(observations, "runtime_activity_observation")
            else ActivityState.UNKNOWN
        ),
        protection=(
            ProtectionClass.CONFLICTING
            if key_conflicts(observations, "protection_indicator_observation")
            else ProtectionClass.UNKNOWN
        ),
    )
