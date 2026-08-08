"""Read-only, bounded inspection of one mypy ``.mypy_cache`` path.

The detector records raw filesystem observations only.  It does not traverse a
workspace, select cleanup candidates, assign risk labels, or inspect runtime
references.  The interpreter maps sufficiently strong structural observations
to separate domain dimensions while preserving unknown safety context.
"""

from __future__ import annotations

import json
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
    NodeKind,
    ObservedNode,
    ProtectionClass,
    Provenance,
    ReclaimPriority,
    RegenerabilityState,
    RegenerationCost,
    ReachabilityState,
)


_DETECTOR_SOURCE = "mypy-cache-detector"
_VERSION_DIRECTORY = re.compile(r"^\d+\.\d+$")
_METADATA_SUFFIX = ".meta.json"
_DATA_SUFFIXES = (".data.json", ".data.ff")


@dataclass(frozen=True)
class MypyCacheDetection:
    """Raw observations for one inspected path; no interpreted domain states."""

    node: ObservedNode
    observations: tuple[Evidence, ...]

    def contract_assessment(self) -> EvidenceAssessment:
        return contract_for(ArtifactKind.MYPY_CACHE).assess(self.observations)

    @property
    def evidence(self) -> EvidenceBundle:
        return self.contract_assessment().bundle


@dataclass(frozen=True)
class MypyCacheInterpretation:
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
    if path.name == ".mypy_cache":
        return _observed(
            "mypy_cache_directory_name_observation",
            "The inspected path has the exact mypy .mypy_cache directory name.",
            value=path.name,
        )
    return _confirmed_absent(
        "mypy_cache_directory_name_observation",
        "The inspected path does not have the exact mypy .mypy_cache directory name.",
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


def _uninspectable(path: Path, node_kind: NodeKind) -> MypyCacheDetection:
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

    return MypyCacheDetection(
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
                "Mypy cache structure could not be inspected.",
            ),
            _not_observed(
                "recreation_input_availability_observation",
                "Recreation-input availability was not inspected.",
            ),
            _not_observed(
                "mypy_cache_marker",
                "Mypy cache metadata/data markers could not be inspected.",
            ),
            _not_observed(
                "cache_layout_observation",
                "Mypy cache version/layout evidence could not be inspected.",
            ),
            *_context_unknown_evidence(),
        ),
    )


def _read_json_object(path: Path) -> tuple[bool, str]:
    try:
        if path.is_symlink() or not path.is_file():
            return False, "not a regular file"
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, PermissionError, UnicodeError, json.JSONDecodeError) as error:
        return False, str(error)
    return (
        isinstance(value, dict),
        "valid JSON object" if isinstance(value, dict) else "JSON value is not an object",
    )


def _read_data_file(path: Path) -> tuple[bool, str]:
    if path.name.endswith(".data.ff"):
        try:
            if path.is_symlink() or not path.is_file():
                return False, "not a regular file"
            if not path.read_bytes():
                return False, "fixed-format data file is empty"
            return True, "non-empty fixed-format data file"
        except (OSError, PermissionError) as error:
            return False, str(error)
    return _read_json_object(path)


def _module_pairs(version_path: Path) -> tuple[tuple[Path, Path], ...]:
    """Find bounded metadata/data pairs in the version directory.

    This intentionally inspects direct module entries and one package-directory
    level only. It is not a recursive workspace traversal; deeper layouts stay
    uncertain until a later bounded extension defines them.
    """

    pairs: list[tuple[Path, Path]] = []

    def collect(directory: Path) -> None:
        try:
            entries = sorted(os.scandir(directory), key=lambda entry: entry.name)
        except (PermissionError, OSError):
            return

        names = {entry.name for entry in entries}
        for entry in entries:
            if not entry.name.endswith(_METADATA_SUFFIX):
                continue
            stem = entry.name[: -len(_METADATA_SUFFIX)]
            metadata_path = Path(entry.path)
            for suffix in _DATA_SUFFIXES:
                data_name = f"{stem}{suffix}"
                if data_name in names:
                    pairs.append((metadata_path, directory / data_name))
                    break

    try:
        with os.scandir(version_path) as entries:
            direct_entries = sorted(entries, key=lambda entry: entry.name)
    except (PermissionError, OSError):
        return ()

    for entry in direct_entries:
        entry_path = Path(entry.path)
        if entry.name.endswith(_METADATA_SUFFIX) or any(
            entry.name.endswith(suffix) for suffix in _DATA_SUFFIXES
        ):
            continue
        try:
            is_directory = entry_path.is_dir() and not entry_path.is_symlink()
        except OSError:
            is_directory = False
        if is_directory:
            collect(entry_path)

    collect(version_path)
    return tuple(pairs)


def inspect_mypy_cache(path: str | os.PathLike[str]) -> MypyCacheDetection:
    """Inspect one path and a bounded portion of its direct cache layout."""

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
    version_paths: list[Path] = []
    directory_read_succeeded = False
    inspection_failed = False

    try:
        with os.scandir(inspected_path) as entries:
            direct_entries = sorted(entries, key=lambda entry: entry.name)
            directory_read_succeeded = True
            for entry in direct_entries:
                entry_path = Path(entry.path)
                if _VERSION_DIRECTORY.fullmatch(entry.name):
                    try:
                        if entry_path.is_dir() and not entry_path.is_symlink():
                            version_paths.append(entry_path)
                        else:
                            inspection_failed = True
                    except OSError:
                        inspection_failed = True
    except (PermissionError, OSError):
        inspection_failed = True

    pair_results: list[tuple[Path, Path, bool, str]] = []
    for version_path in version_paths:
        pairs = _module_pairs(version_path)
        for metadata_path, data_path in pairs:
            metadata_ok, metadata_reason = _read_json_object(metadata_path)
            data_ok, data_reason = _read_data_file(data_path)
            pair_results.append(
                (
                    metadata_path,
                    data_path,
                    metadata_ok and data_ok,
                    f"metadata: {metadata_reason}; data: {data_reason}",
                )
            )

    valid_pairs = [result for result in pair_results if result[2]]
    invalid_pairs = [result for result in pair_results if not result[2]]
    if valid_pairs:
        marker_observation = _observed(
            "mypy_cache_marker",
            "A readable mypy module metadata/data pair was observed.",
            value="module-metadata-data-pair",
        )
        layout_observation = _observed(
            "cache_layout_observation",
            "A Python-version directory with a readable mypy module pair was observed.",
            value=version_paths[0].name,
        )
        generator_observation = _observed(
            "generator_indicator_observation",
            "Mypy cache structural metadata and data files were observed.",
            value="mypy-cache-module-pair",
        )
    elif invalid_pairs:
        reason = invalid_pairs[0][3]
        marker_observation = _failed(
            "mypy_cache_marker",
            f"A candidate mypy metadata/data pair could not be validated: {reason}.",
        )
        layout_observation = _failed(
            "cache_layout_observation",
            "A mypy version directory contained an incomplete or corrupt module pair.",
        )
        generator_observation = _failed(
            "generator_indicator_observation",
            "Mypy cache structure could not be validated.",
        )
    elif version_paths:
        marker_observation = _observed(
            "mypy_cache_marker",
            "A Python-version directory was observed without a readable module metadata/data pair.",
            confidence=Confidence.LOW,
            value="version-directory-only",
        )
        layout_observation = _observed(
            "cache_layout_observation",
            "Only a weak mypy cache layout signal was observed.",
            confidence=Confidence.LOW,
            value="version-directory-only",
        )
        generator_observation = _observed(
            "generator_indicator_observation",
            "Only a weak mypy cache layout signal was observed.",
            confidence=Confidence.LOW,
            value="version-directory-only",
        )
    elif directory_read_succeeded:
        marker_observation = _confirmed_absent(
            "mypy_cache_marker",
            "No readable mypy module metadata/data pair was observed.",
        )
        layout_observation = _confirmed_absent(
            "cache_layout_observation",
            "No Python-version directory was observed at the cache root.",
        )
        generator_observation = _confirmed_absent(
            "generator_indicator_observation",
            "No mypy cache structural evidence was observed.",
        )
    else:
        marker_observation = _failed(
            "mypy_cache_marker",
            "The directory could not be read to inspect mypy cache structure.",
        )
        layout_observation = _failed(
            "cache_layout_observation",
            "The directory could not be read to inspect mypy cache layout.",
        )
        generator_observation = _failed(
            "generator_indicator_observation",
            "Mypy cache structure could not be inspected reliably.",
        )

    if inspection_failed and not invalid_pairs:
        marker_observation = _failed(
            "mypy_cache_marker",
            "A directory observation failed while inspecting mypy cache structure.",
        )
        layout_observation = _failed(
            "cache_layout_observation",
            "A directory observation failed while inspecting mypy cache layout.",
        )

    observations.extend(
        (
            _observed(
                "metadata_readability_observation",
                "The cache root and bounded direct layout observations were readable.",
            )
            if directory_read_succeeded and not inspection_failed
            else _failed(
                "metadata_readability_observation",
                "The cache root or bounded layout observations could not be read reliably.",
            ),
            generator_observation,
            _unknown(
                "recreation_input_availability_observation",
                "This detector does not inspect source inputs, dependencies, or mypy configuration.",
            ),
            marker_observation,
            layout_observation,
            *_context_unknown_evidence(),
        )
    )

    return MypyCacheDetection(
        node=ObservedNode(
            path=str(inspected_path),
            kind=NodeKind.DIRECTORY,
            protection=ProtectionClass.UNKNOWN,
        ),
        observations=tuple(observations),
    )


def interpret_mypy_cache(detection: MypyCacheDetection) -> MypyCacheInterpretation:
    """Interpret structural mypy evidence into separate domain dimensions."""

    requirements = requirements_by_key(ArtifactKind.MYPY_CACHE)
    observations = detection.observations
    structural_keys = (
        "mypy_cache_directory_name_observation",
        "mypy_cache_marker",
        "cache_layout_observation",
    )
    structural_valid = all(
        positive_evidence_meets(observations, key, requirements)
        for key in structural_keys
    )
    structural_conflict = any(key_conflicts(observations, key) for key in structural_keys)
    structural_uncertainty = any(
        key_has_uncertainty(observations, key)
        for key in structural_keys
    )
    provenance = (
        Provenance(
            ecosystem="python",
            generator="mypy",
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

    return MypyCacheInterpretation(
        provenance=provenance,
        regenerability=regenerability,
        regeneration_cost=RegenerationCost.UNKNOWN,
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
