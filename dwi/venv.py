"""Bounded read-only analysis of one Python virtual-environment candidate."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from .contracts import ArtifactKind, EvidenceAssessment, contract_for, requirements_by_key
from .detector_support import (
    activity_from_evidence,
    confirmed_absent_evidence,
    context_unknown_evidence,
    failed_evidence,
    key_conflicts,
    key_has_uncertainty,
    not_observed_evidence,
    observed_evidence,
    observed_node_kind,
    protection_from_evidence,
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


_DETECTOR_SOURCE = "python-venv-detector"
_VENV_NAMES = {".venv", "venv"}


@dataclass(frozen=True)
class PythonVenvDetection:
    """Raw observations for exactly one candidate path."""

    node: ObservedNode
    observations: tuple[Evidence, ...]

    def contract_assessment(self) -> EvidenceAssessment:
        return contract_for(ArtifactKind.PYTHON_VENV).assess(self.observations)

    @property
    def evidence(self) -> EvidenceBundle:
        return self.contract_assessment().bundle


@dataclass(frozen=True)
class PythonVenvInterpretation:
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
    if path.name in _VENV_NAMES:
        return _observed(
            "python_venv_directory_name_observation",
            "The inspected path has the exact .venv or venv directory name.",
            value=path.name,
        )
    return _confirmed_absent(
        "python_venv_directory_name_observation",
        "The inspected path does not have the exact .venv or venv directory name.",
    )


def _context_for_uninspectable(path: Path, node_kind: NodeKind) -> tuple[Evidence, ...]:
    path_observation = (
        _not_observed("path_object_observation", "The inspected path was not observed.")
        if node_kind is NodeKind.UNKNOWN
        else _observed(
            "path_object_observation",
            f"The inspected path is a {node_kind.value}, not a directory.",
            value=node_kind.value,
        )
    )
    metadata = (
        _failed(
            "metadata_readability_observation",
            "The virtual-environment path could not be read reliably.",
        )
    )
    return (
        _name_observation(path),
        path_observation,
        metadata,
        _not_observed("generator_indicator_observation", "Virtual-environment markers could not be inspected."),
        _unknown(
            "recreation_input_availability_observation",
            "Project recreation inputs outside the candidate were not inspected.",
        ),
        _not_observed("pyvenv_cfg_marker", "pyvenv.cfg could not be inspected."),
        _not_observed("interpreter_layout_observation", "The Windows interpreter layout could not be inspected."),
        _not_observed("project_metadata_observation", "Project metadata was not inspected outside the candidate boundary."),
        *context_unknown_evidence(_DETECTOR_SOURCE),
    )


def _read_pyvenv_cfg(path: Path) -> tuple[Evidence, bool]:
    cfg = path / "pyvenv.cfg"
    try:
        if cfg.is_symlink() or not cfg.is_file():
            return _confirmed_absent("pyvenv_cfg_marker", "No regular pyvenv.cfg file was observed."), False
        text = cfg.read_text(encoding="utf-8", errors="replace")
    except (PermissionError, OSError) as error:
        return _failed("pyvenv_cfg_marker", f"Could not inspect pyvenv.cfg: {error}."), False

    values: dict[str, str] = {}
    for line in text.splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip().lower()] = value.strip()
    valid = (
        bool(values.get("home"))
        and bool(values.get("version"))
        and values.get("include-system-site-packages", "").lower() in {"true", "false"}
    )
    if not valid:
        return _failed("pyvenv_cfg_marker", "pyvenv.cfg was present but its required fields were invalid."), False
    return (
        _observed(
            "pyvenv_cfg_marker",
            "A readable pyvenv.cfg with home, version, and include-system-site-packages fields was observed.",
            value="pyvenv.cfg",
        ),
        True,
    )


def _interpreter_layout(path: Path) -> tuple[Evidence, bool]:
    scripts = path / "Scripts"
    interpreter = scripts / "python.exe"
    try:
        if scripts.is_symlink() or not scripts.is_dir() or interpreter.is_symlink() or not interpreter.is_file():
            return _confirmed_absent(
                "interpreter_layout_observation",
                "The expected Windows Scripts/python.exe layout was not observed.",
            ), False
        if interpreter.stat().st_size == 0:
            return _observed(
                "interpreter_layout_observation",
                "Scripts/python.exe was observed but is empty and cannot establish a valid interpreter layout.",
                confidence=Confidence.LOW,
                value="Scripts/python.exe",
            ), False
    except (PermissionError, OSError) as error:
        return _failed("interpreter_layout_observation", f"Could not inspect the Windows interpreter layout: {error}."), False
    return (
        _observed(
            "interpreter_layout_observation",
            "A non-empty regular Windows Scripts/python.exe entry was observed.",
            value="Scripts/python.exe",
        ),
        True,
    )


def _project_metadata(path: Path) -> Evidence:
    """Inspect only metadata physically inside the candidate, never its parent."""

    names = ("pyproject.toml", "requirements.txt", "requirements-dev.txt", "Pipfile", "poetry.lock")
    try:
        for name in names:
            candidate = path / name
            if candidate.is_symlink():
                return _unknown(
                    "project_metadata_observation",
                    f"Candidate-local project metadata {name} is symlinked and was not followed.",
                )
            if candidate.is_file() and candidate.stat().st_size > 0:
                return _observed(
                    "project_metadata_observation",
                    f"Candidate-local project metadata {name} was observed; no parent context was inspected.",
                    value=name,
                )
    except (PermissionError, OSError) as error:
        return _failed("project_metadata_observation", f"Candidate-local project metadata could not be inspected: {error}.")
    return _unknown(
        "project_metadata_observation",
        "Project metadata outside the virtual-environment candidate was intentionally not inspected.",
    )


def inspect_python_venv(path: str | os.PathLike[str]) -> PythonVenvDetection:
    """Inspect one .venv/venv path without reading outside it or mutating it."""

    inspected_path = Path(path)
    node_kind = observed_node_kind(inspected_path)
    if node_kind is not NodeKind.DIRECTORY:
        return PythonVenvDetection(
            node=ObservedNode(str(inspected_path), node_kind, ProtectionClass.UNKNOWN),
            observations=_context_for_uninspectable(inspected_path, node_kind),
        )

    name = _name_observation(inspected_path)
    cfg_evidence, cfg_valid = _read_pyvenv_cfg(inspected_path)
    layout_evidence, layout_valid = _interpreter_layout(inspected_path)
    try:
        metadata = _observed(
            "metadata_readability_observation",
            "The virtual-environment directory and bounded entries were readable.",
        )
    except (PermissionError, OSError):
        metadata = _failed("metadata_readability_observation", "The virtual-environment entries could not be read.")

    observations = (
        name,
        _observed("path_object_observation", "The inspected path is a directory.", value=NodeKind.DIRECTORY.value),
        metadata,
        _observed(
            "generator_indicator_observation",
            "A valid local pyvenv.cfg and Windows interpreter layout were observed.",
            value="python-venv",
        )
        if cfg_valid and layout_valid
        else _observed(
            "generator_indicator_observation",
            "Only partial Python virtual-environment structure was observed.",
            confidence=Confidence.LOW,
            value="python-venv-partial",
        ),
        _unknown(
            "recreation_input_availability_observation",
            "Project and lockfile inputs outside the candidate were intentionally not inspected.",
        ),
        cfg_evidence,
        layout_evidence,
        _project_metadata(inspected_path),
        *context_unknown_evidence(_DETECTOR_SOURCE),
    )
    return PythonVenvDetection(
        node=ObservedNode(str(inspected_path), NodeKind.DIRECTORY, ProtectionClass.UNKNOWN),
        observations=observations,
    )


def interpret_python_venv(detection: PythonVenvDetection) -> PythonVenvInterpretation:
    """Interpret local venv structure while keeping regeneration conditional."""

    requirements = requirements_by_key(ArtifactKind.PYTHON_VENV)
    observations = detection.observations
    structural_keys = (
        "python_venv_directory_name_observation",
        "pyvenv_cfg_marker",
        "interpreter_layout_observation",
    )
    structural_valid = all(
        positive_evidence_meets(observations, key, requirements)
        for key in structural_keys
    )
    structural_conflict = any(key_conflicts(observations, key) for key in structural_keys)
    structural_uncertainty = any(key_has_uncertainty(observations, key) for key in structural_keys)
    provenance = (
        Provenance(
            ecosystem="python",
            generator="python-virtual-environment",
            confidence=Confidence.HIGH,
            evidence_keys=structural_keys,
        )
        if structural_valid and not structural_conflict and not structural_uncertainty
        else None
    )
    if structural_conflict:
        regenerability = RegenerabilityState.CONFLICTING
        cost = RegenerationCost.UNKNOWN
    elif structural_valid and not structural_uncertainty:
        regenerability = RegenerabilityState.CONDITIONALLY_REPRODUCIBLE
        cost = RegenerationCost.UNKNOWN
    else:
        regenerability = RegenerabilityState.UNKNOWN
        cost = RegenerationCost.UNKNOWN
    return PythonVenvInterpretation(
        provenance=provenance,
        regenerability=regenerability,
        regeneration_cost=cost,
        reachability=reachability_from_evidence(observations, requirements),
        activity=activity_from_evidence(observations),
        protection=protection_from_evidence(observations),
    )
