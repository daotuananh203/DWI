"""Detector-neutral evidence contracts for the initial artifact catalog.

Contracts describe required evidence shape and minimum confidence only. They do
not assign risk labels or perform any filesystem or detector work.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from .domain import Confidence, Evidence, EvidenceBundle, EvidenceRequirement


class Ecosystem(str, Enum):
    PYTHON = "python"
    NODE = "node"


class ArtifactKind(str, Enum):
    PYCACHE = "pycache"
    PYTEST_CACHE = "pytest_cache"
    MYPY_CACHE = "mypy_cache"
    RUFF_CACHE = "ruff_cache"
    PYTHON_VENV = "python_venv"
    NODE_MODULES = "node_modules"
    DIST = "dist"
    BUILD = "build"
    NEXT_BUILD = "next_build"


@dataclass(frozen=True)
class EvidenceContract:
    artifact: ArtifactKind
    ecosystem: Ecosystem
    requirements: tuple[EvidenceRequirement, ...]
    evidence_notes: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        keys = [requirement.key for requirement in self.requirements]
        if len(keys) != len(set(keys)):
            raise ValueError("contract requirements must have unique keys")

    def bind(self, observations: tuple[Evidence, ...]) -> EvidenceBundle:
        """Bind observations to this contract without making a policy conclusion."""

        return EvidenceBundle(observations=observations, requirements=self.requirements)

    def assess(self, observations: tuple[Evidence, ...]) -> "EvidenceAssessment":
        return EvidenceAssessment(contract=self, bundle=self.bind(observations))


@dataclass(frozen=True)
class EvidenceAssessment:
    contract: EvidenceContract
    bundle: EvidenceBundle

    @property
    def missing_keys(self) -> frozenset[str]:
        return self.bundle.missing_keys

    @property
    def confidence_shortfalls(self) -> frozenset[str]:
        return self.bundle.confidence_shortfalls

    @property
    def has_uncertainty(self) -> bool:
        return self.bundle.has_uncertainty

    @property
    def has_conflicts(self) -> bool:
        return self.bundle.has_conflicts

    @property
    def evidence_sufficient(self) -> bool:
        """Whether the evidence satisfies this contract, not whether it is safe."""

        return (
            self.bundle.is_complete
            and not self.missing_keys
            and not self.confidence_shortfalls
            and not self.has_uncertainty
            and not self.has_conflicts
        )


_COMMON_KEYS = (
    "path_object_observation",
    "metadata_readability_observation",
    "generator_indicator_observation",
    "recreation_input_observation",
    "reference_check_observation",
    "runtime_activity_observation",
    "protection_indicator_observation",
)

_ARTIFACT_KEYS: dict[ArtifactKind, tuple[str, ...]] = {
    ArtifactKind.PYCACHE: ("python_bytecode_marker", "python_source_reference_observation"),
    ArtifactKind.PYTEST_CACHE: ("pytest_cache_marker", "cache_layout_observation"),
    ArtifactKind.MYPY_CACHE: ("mypy_cache_marker", "cache_layout_observation"),
    ArtifactKind.RUFF_CACHE: ("ruff_cache_marker", "cache_layout_observation"),
    ArtifactKind.PYTHON_VENV: (
        "pyvenv_cfg_marker",
        "interpreter_layout_observation",
        "project_metadata_observation",
    ),
    ArtifactKind.NODE_MODULES: (
        "package_manifest_observation",
        "dependency_tree_observation",
        "package_manager_indicator",
    ),
    ArtifactKind.DIST: (
        "build_output_marker",
        "build_configuration_observation",
        "source_input_observation",
    ),
    ArtifactKind.BUILD: (
        "build_output_marker",
        "build_configuration_observation",
        "source_input_observation",
    ),
    ArtifactKind.NEXT_BUILD: (
        "next_metadata_marker",
        "build_output_marker",
        "project_configuration_observation",
    ),
}


def _requirements(artifact: ArtifactKind) -> tuple[EvidenceRequirement, ...]:
    keys = _COMMON_KEYS + _ARTIFACT_KEYS[artifact]
    return tuple(EvidenceRequirement(key, Confidence.HIGH) for key in keys)


_CONTRACTS: dict[ArtifactKind, EvidenceContract] = {
    artifact: EvidenceContract(
        artifact=artifact,
        ecosystem=Ecosystem.PYTHON if artifact in {
            ArtifactKind.PYCACHE,
            ArtifactKind.PYTEST_CACHE,
            ArtifactKind.MYPY_CACHE,
            ArtifactKind.RUFF_CACHE,
            ArtifactKind.PYTHON_VENV,
        } else Ecosystem.NODE,
        requirements=_requirements(artifact),
        evidence_notes=(
            "Evidence keys describe observations only; no key maps directly to a domain state or RiskLabel.",
            "Confirmed references, uncertainty, or conflicts must fail closed in policy evaluation.",
        ),
    )
    for artifact in ArtifactKind
}


def contract_for(artifact: ArtifactKind) -> EvidenceContract:
    return _CONTRACTS[artifact]


def all_contracts() -> tuple[EvidenceContract, ...]:
    return tuple(_CONTRACTS[artifact] for artifact in ArtifactKind)
