"""Bounded, detector-neutral analysis for approved developer cache roots."""

from __future__ import annotations

import os
import stat
from dataclasses import dataclass
from pathlib import Path

from .contracts import ArtifactKind, contract_for, requirements_by_key
from .detector_support import (
    activity_from_evidence,
    context_unknown_evidence,
    failed_evidence,
    key_conflicts,
    key_has_uncertainty,
    not_observed_evidence,
    observed_evidence,
    positive_evidence_meets,
    protection_from_evidence,
    reachability_from_evidence,
)
from .domain import (
    ActivityState,
    Confidence,
    Evidence,
    EvidenceBundle,
    NodeKind,
    ObservationStatus,
    ProtectionClass,
    Provenance,
    ReclaimPriority,
    RegenerabilityState,
    RegenerationCost,
    ReachabilityState,
    ObservedNode,
)
from .scan_control import ScanBudget


_SOURCE = "global-storage-observer"
_GLOBAL_ARTIFACTS = {
    ArtifactKind.PIP_CACHE,
    ArtifactKind.UV_CACHE,
    ArtifactKind.NPM_CACHE,
    ArtifactKind.PNPM_CACHE,
    ArtifactKind.YARN_CACHE,
}


@dataclass(frozen=True)
class GlobalStorageDetection:
    artifact: ArtifactKind
    node: ObservedNode
    evidence: EvidenceBundle


@dataclass(frozen=True)
class GlobalStorageInterpretation:
    provenance: Provenance | None
    regenerability: RegenerabilityState
    regeneration_cost: RegenerationCost
    reachability: ReachabilityState
    activity: ActivityState
    protection: ProtectionClass
    reclaim_priority: ReclaimPriority = ReclaimPriority.UNKNOWN


def _observed(key: str, description: str, *, value: str | None = None) -> Evidence:
    return observed_evidence(_SOURCE, key, description, value=value)


def _failed(key: str, description: str) -> Evidence:
    return failed_evidence(_SOURCE, key, description)


def _is_reparse(metadata: os.stat_result) -> bool:
    return bool(
        getattr(metadata, "st_file_attributes", 0)
        & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    )


def _limit_error(budget: ScanBudget | None) -> str | None:
    if budget is None or not budget.stopped():
        return None
    return f"scan-limit:{budget.termination.value}"


def _metadata_identity(metadata: os.stat_result) -> tuple[int, int, int, bool]:
    return (
        getattr(metadata, "st_dev", 0),
        getattr(metadata, "st_ino", 0),
        stat.S_IFMT(metadata.st_mode),
        _is_reparse(metadata),
    )


def _metadata_matches(first: os.stat_result, second: os.stat_result) -> bool:
    first_identity = _metadata_identity(first)
    second_identity = _metadata_identity(second)
    if first_identity[2:] != second_identity[2:]:
        return False
    if first_identity[:2] == (0, 0) or second_identity[:2] == (0, 0):
        return True
    return first_identity[:2] == second_identity[:2]


def _within_root(root: Path, path: Path) -> bool:
    try:
        return os.path.commonpath((os.path.abspath(root), os.path.abspath(path))) == os.path.abspath(root)
    except ValueError:
        return False


def _validate_directory(
    path: Path,
    *,
    expected: os.stat_result | None = None,
) -> tuple[os.stat_result | None, str | None]:
    try:
        metadata = os.lstat(path)
    except (OSError, ValueError) as error:
        return None, type(error).__name__
    if stat.S_ISLNK(metadata.st_mode):
        return metadata, "symlink"
    if _is_reparse(metadata):
        return metadata, "reparse"
    if not stat.S_ISDIR(metadata.st_mode):
        return metadata, "not-directory"
    if expected is not None and not _metadata_matches(expected, metadata):
        return metadata, "traversal-race"
    return metadata, None


def _node_kind(metadata: os.stat_result | None) -> NodeKind:
    if metadata is None:
        return NodeKind.INACCESSIBLE
    if stat.S_ISLNK(metadata.st_mode):
        return NodeKind.SYMLINK
    if _is_reparse(metadata):
        return NodeKind.REPARSE_POINT
    if stat.S_ISDIR(metadata.st_mode):
        return NodeKind.DIRECTORY
    if stat.S_ISREG(metadata.st_mode):
        return NodeKind.FILE
    return NodeKind.UNKNOWN


def _direct_entries(
    path: Path,
    *,
    budget: ScanBudget | None = None,
    containment_root: Path | None = None,
    expected: os.stat_result | None = None,
) -> tuple[dict[str, str], bool, str | None]:
    entries: dict[str, str] = {}
    ambiguous = False
    root = containment_root or path
    current_metadata, validation_error = _validate_directory(path, expected=expected)
    if validation_error is not None:
        return entries, True, validation_error
    try:
        with os.scandir(path) as scanned:
            observed: list[tuple[os.DirEntry[str], os.stat_result]] = []
            for entry in scanned:
                if budget is not None and budget.stopped():
                    return entries, ambiguous, _limit_error(budget)
                child = Path(entry.path)
                if not _within_root(root, child):
                    return entries, True, "outside-approved-root"
                metadata = entry.stat(follow_symlinks=False)
                child_after = os.lstat(child)
                if not _metadata_matches(metadata, child_after):
                    return entries, True, "traversal-race"
                metadata = child_after
                if budget is not None and not budget.observe_node(is_file=stat.S_ISREG(metadata.st_mode)):
                    return entries, ambiguous, _limit_error(budget)
                observed.append((entry, metadata))
            for entry, metadata in sorted(observed, key=lambda item: (item[0].name.casefold(), item[0].name)):
                if stat.S_ISLNK(metadata.st_mode) or _is_reparse(metadata):
                    ambiguous = True
                    continue
                if stat.S_ISDIR(metadata.st_mode):
                    entries[entry.name] = "directory"
                elif stat.S_ISREG(metadata.st_mode):
                    entries[entry.name] = "file"
                else:
                    entries[entry.name] = "other"
            after_scan = os.lstat(path)
            if current_metadata is None or not _metadata_matches(current_metadata, after_scan):
                return entries, True, "traversal-race"
    except (OSError, ValueError) as error:
        return entries, ambiguous, type(error).__name__
    return entries, ambiguous, None


def _nested_layout(path: Path, name: str, *, budget: ScanBudget | None = None) -> tuple[dict[str, str], bool, str | None]:
    if budget is not None and budget.stopped():
        return {}, False, _limit_error(budget)
    child = path / name
    try:
        metadata = os.lstat(child)
    except (OSError, ValueError) as error:
        return {}, False, type(error).__name__
    if stat.S_ISLNK(metadata.st_mode) or _is_reparse(metadata):
        return {}, True, None
    if not stat.S_ISDIR(metadata.st_mode):
        return {}, False, "wrong-type"
    return _direct_entries(child, budget=budget, containment_root=path, expected=metadata)


def _layout_is_valid(
    artifact: ArtifactKind,
    path: Path,
    entries: dict[str, str],
    *,
    budget: ScanBudget | None = None,
) -> tuple[bool, str]:
    names = {name.casefold() for name in entries}
    if artifact is ArtifactKind.PIP_CACHE:
        known = names & {"http-v2", "http", "wheels", "selfcheck"}
        return (
            len(known) >= 2 and any(entries[name] == "directory" for name in entries if name.casefold() in {"http-v2", "http", "wheels"}),
            "pip cache marker directories and selfcheck/wheel layout observed",
        )
    if artifact is ArtifactKind.UV_CACHE:
        known = [name for name in entries if name.casefold().startswith(("archive-v", "wheels-v", "simple-v", "interpreter-v"))]
        return len(known) >= 2, "uv versioned cache directories observed"
    if artifact is ArtifactKind.NPM_CACHE:
        if entries.get("content-v2") == "directory" and entries.get("index-v5") == "directory":
            return True, "npm content-v2 and index-v5 layout observed"
        if entries.get("_cacache") == "directory":
            nested, ambiguous, error = _nested_layout(path, "_cacache", budget=budget)
            if error is not None:
                return False, f"nested npm cache structure failed: {error}"
            if not error and not ambiguous and nested.get("content-v2") == "directory" and nested.get("index-v5") == "directory":
                return True, "npm _cacache content-v2 and index-v5 layout observed"
        return False, "npm cache content/index layout was not confirmed"
    if artifact is ArtifactKind.PNPM_CACHE:
        for version in entries:
            if version.casefold().startswith("v") and entries[version] == "directory":
                nested, ambiguous, error = _nested_layout(path, version, budget=budget)
                if error is not None:
                    return False, f"nested pnpm cache structure failed: {error}"
                if not error and not ambiguous and nested.get("files") == "directory" and nested.get("index") == "directory":
                    return True, "pnpm versioned files and index layout observed"
        return False, "pnpm versioned files/index layout was not confirmed"
    if artifact is ArtifactKind.YARN_CACHE:
        for child, kind in entries.items():
            if kind != "directory":
                continue
            nested, ambiguous, error = _nested_layout(path, child, budget=budget)
            if error is not None:
                return False, f"nested yarn cache structure failed: {error}"
            if not error and not ambiguous and ".yarn-metadata.json" in nested and nested[".yarn-metadata.json"] == "file":
                return True, "yarn package cache metadata was observed"
        return False, "yarn package metadata layout was not confirmed"
    raise ValueError(f"unsupported global storage artifact: {artifact}")


def inspect_global_storage(
    path: str | os.PathLike[str],
    artifact: ArtifactKind,
    *,
    approved_root: bool = False,
    budget: ScanBudget | None = None,
) -> GlobalStorageDetection:
    """Inspect one explicitly approved cache root without recursive discovery."""

    if artifact not in _GLOBAL_ARTIFACTS:
        raise ValueError(f"unsupported global storage artifact: {artifact}")
    inspected_path = Path(path)
    observations: list[Evidence] = [
        _observed("path_object_observation", "The explicit global-storage path was supplied to the bounded observer."),
        _observed("metadata_readability_observation", "Global-storage metadata observation was attempted."),
        _observed(
            "global_storage_path_observation",
            "The path belongs to an approved developer-storage location." if approved_root else "The path was not supplied by the approved system-storage scope.",
            value=str(inspected_path),
        ) if approved_root else _failed("global_storage_path_observation", "The path was not supplied by the approved system-storage scope."),
        _observed("generator_indicator_observation", "The storage family was selected by an explicit system-storage contract.", value=artifact.value),
        _observed("protection_indicator_observation", "No repository or system protection marker was established by this bounded cache observer.", value=ProtectionClass.ORDINARY.value),
    ]
    if budget is not None and budget.stopped():
        node = ObservedNode(str(inspected_path), NodeKind.UNKNOWN, ProtectionClass.UNKNOWN)
        observations.extend(
            (
                _failed("global_storage_marker_observation", f"Global-storage inspection stopped: {_limit_error(budget)}."),
                _failed("global_storage_structure_observation", f"Global-storage structure was not observed: {_limit_error(budget)}."),
                not_observed_evidence(_SOURCE, "recreation_input_availability_observation", "Recreation inputs are outside this cache root."),
                *context_unknown_evidence(_SOURCE),
            )
        )
        return GlobalStorageDetection(artifact, node, contract_for(artifact).bind(tuple(observations)))
    try:
        metadata = os.lstat(inspected_path)
    except (OSError, ValueError) as error:
        node = ObservedNode(str(inspected_path), NodeKind.INACCESSIBLE, ProtectionClass.UNKNOWN)
        observations.extend(
            (
                _failed("metadata_readability_observation", f"The global-storage path could not be observed: {type(error).__name__}."),
                _failed("global_storage_marker_observation", "The global-storage marker could not be observed."),
                _failed("global_storage_structure_observation", "The global-storage structure could not be observed."),
                not_observed_evidence(_SOURCE, "recreation_input_availability_observation", "Recreation inputs are outside this cache root."),
                *context_unknown_evidence(_SOURCE),
            )
        )
        return GlobalStorageDetection(artifact, node, contract_for(artifact).bind(tuple(observations)))
    if stat.S_ISLNK(metadata.st_mode) or _is_reparse(metadata):
        node_kind = NodeKind.SYMLINK if stat.S_ISLNK(metadata.st_mode) else NodeKind.REPARSE_POINT
        node = ObservedNode(str(inspected_path), node_kind, ProtectionClass.UNKNOWN)
        observations.extend(
            (
                _failed("global_storage_marker_observation", "A link or reparse point was not followed."),
                _failed("global_storage_structure_observation", "Global-storage structure is ambiguous."),
                not_observed_evidence(_SOURCE, "recreation_input_availability_observation", "Recreation inputs are outside this cache root."),
                *context_unknown_evidence(_SOURCE),
            )
        )
        return GlobalStorageDetection(artifact, node, contract_for(artifact).bind(tuple(observations)))
    if not stat.S_ISDIR(metadata.st_mode):
        node = ObservedNode(str(inspected_path), NodeKind.FILE, ProtectionClass.UNKNOWN)
        observations.extend(
            (
                _failed("global_storage_marker_observation", "The approved global-storage path is not a directory."),
                _failed("global_storage_structure_observation", "Global-storage structure is ambiguous."),
                not_observed_evidence(_SOURCE, "recreation_input_availability_observation", "Recreation inputs are outside this cache root."),
                *context_unknown_evidence(_SOURCE),
            )
        )
        return GlobalStorageDetection(artifact, node, contract_for(artifact).bind(tuple(observations)))

    pre_enum_metadata, pre_enum_error = _validate_directory(inspected_path, expected=metadata)
    if pre_enum_error is not None:
        reason = f"Global-storage root validation failed before enumeration: {pre_enum_error}."
        node = ObservedNode(str(inspected_path), _node_kind(pre_enum_metadata), ProtectionClass.UNKNOWN)
        observations.extend(
            (
                _failed("global_storage_marker_observation", reason),
                _failed("global_storage_structure_observation", reason),
                not_observed_evidence(_SOURCE, "recreation_input_availability_observation", "Recreation inputs are outside this cache root."),
                *context_unknown_evidence(_SOURCE),
            )
        )
        return GlobalStorageDetection(artifact, node, contract_for(artifact).bind(tuple(observations)))

    entries, ambiguous, error = _direct_entries(
        inspected_path,
        budget=budget,
        containment_root=inspected_path,
        expected=pre_enum_metadata,
    )
    valid, description = _layout_is_valid(artifact, inspected_path, entries, budget=budget) if not error and not ambiguous else (
        False,
        f"Global-storage structure was not fully observed: {error}." if error else "Global-storage structure was unreadable or ambiguous.",
    )
    if valid:
        marker = _observed("global_storage_marker_observation", "A tool-specific global cache marker was observed.", value=artifact.value)
        structure = _observed("global_storage_structure_observation", description, value=",".join(sorted(entries)))
        node = ObservedNode(str(inspected_path), NodeKind.DIRECTORY, ProtectionClass.ORDINARY)
    else:
        marker = _failed("global_storage_marker_observation", "Tool-specific global cache markers were not sufficient to identify this root.")
        structure = _failed("global_storage_structure_observation", description)
        node = ObservedNode(str(inspected_path), NodeKind.DIRECTORY, ProtectionClass.UNKNOWN)
    observations.extend(
        (
            marker,
            structure,
            not_observed_evidence(_SOURCE, "recreation_input_availability_observation", "Recreation inputs are outside this cache root."),
            *context_unknown_evidence(_SOURCE),
        )
    )
    return GlobalStorageDetection(artifact, node, contract_for(artifact).bind(tuple(observations)))


def interpret_global_storage(detection: GlobalStorageDetection) -> GlobalStorageInterpretation:
    requirements = requirements_by_key(detection.artifact)
    identity_keys = (
        "global_storage_path_observation",
        "global_storage_marker_observation",
        "global_storage_structure_observation",
    )
    identity_valid = all(
        positive_evidence_meets(detection.evidence.observations, key, requirements)
        for key in identity_keys
    ) and not any(
        key_conflicts(detection.evidence.observations, key) or key_has_uncertainty(detection.evidence.observations, key)
        for key in identity_keys
    )
    provenance = (
        Provenance(
            ecosystem="python" if detection.artifact in {ArtifactKind.PIP_CACHE, ArtifactKind.UV_CACHE} else "node",
            generator=detection.artifact.value,
            confidence=Confidence.HIGH,
            evidence_keys=identity_keys,
        )
        if identity_valid
        else None
    )
    if detection.evidence.has_conflicts:
        regenerability = RegenerabilityState.CONFLICTING
    elif identity_valid:
        regenerability = RegenerabilityState.CONDITIONALLY_REPRODUCIBLE
    else:
        regenerability = RegenerabilityState.UNKNOWN
    return GlobalStorageInterpretation(
        provenance=provenance,
        regenerability=regenerability,
        regeneration_cost=RegenerationCost.UNKNOWN,
        reachability=reachability_from_evidence(detection.evidence.observations, requirements),
        activity=activity_from_evidence(detection.evidence.observations),
        protection=protection_from_evidence(detection.evidence.observations),
    )
