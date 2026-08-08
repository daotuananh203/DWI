"""Synthetic raw-observation fixtures for evidence contract tests.

No fixture reads, creates, resolves, or deletes a real filesystem path. Domain
states are optional expected outputs and are never used as contract inputs.
"""

from __future__ import annotations

from dataclasses import dataclass, replace

from .contracts import ArtifactKind, EvidenceAssessment, contract_for
from .domain import (
    ActivityState,
    Confidence,
    Evidence,
    EvidencePolarity,
    NodeKind,
    ObservationStatus,
    ProtectionClass,
    Provenance,
    ReclaimPriority,
    RegenerabilityState,
    RegenerationCost,
    ReachabilityState,
)


@dataclass(frozen=True)
class ExpectedDomainInterpretation:
    """Expected output reserved for future interpreter tests, not fixture input."""

    provenance: Provenance | None = None
    regenerability: RegenerabilityState | None = None
    regeneration_cost: RegenerationCost | None = None
    reachability: ReachabilityState | None = None
    activity: ActivityState | None = None
    protection: ProtectionClass | None = None
    reclaim_priority: ReclaimPriority | None = None


@dataclass(frozen=True)
class SyntheticArtifactFixture:
    fixture_id: str
    artifact: ArtifactKind
    synthetic_path: str
    description: str
    observations: tuple[Evidence, ...]
    observed_node_kind: NodeKind = NodeKind.DIRECTORY
    expected_interpretation: ExpectedDomainInterpretation | None = None
    adversarial: bool = False

    def assess_contract(self) -> EvidenceAssessment:
        """Assess raw observations only; expected interpretation is intentionally ignored."""

        return contract_for(self.artifact).assess(self.observations)


def _evidence(
    key: str,
    description: str,
    *,
    status: ObservationStatus = ObservationStatus.OBSERVED,
    polarity: EvidencePolarity = EvidencePolarity.SUPPORTS,
    confidence: Confidence = Confidence.HIGH,
    value: str | None = None,
) -> Evidence:
    return Evidence(
        key=key,
        source="synthetic-fixture",
        description=description,
        observation_status=status,
        polarity=polarity,
        confidence=confidence,
        value=value,
    )


def _normal_fixture(artifact: ArtifactKind) -> SyntheticArtifactFixture:
    contract = contract_for(artifact)
    observations: list[Evidence] = []
    for requirement in contract.requirements:
        if requirement.key == "reference_check_observation":
            observations.append(
                _evidence(
                    requirement.key,
                    "Synthetic active check confirmed no references.",
                    status=ObservationStatus.CONFIRMED_ABSENT,
                    polarity=EvidencePolarity.CONTRADICTS,
                    value="no references confirmed",
                )
            )
        else:
            observations.append(
                _evidence(
                    requirement.key,
                    f"Synthetic high-confidence observation for {requirement.key}.",
                    value=f"synthetic:{artifact.value}:{requirement.key}",
                )
            )

    python_artifacts = {
        ArtifactKind.PYCACHE,
        ArtifactKind.PYTEST_CACHE,
        ArtifactKind.MYPY_CACHE,
        ArtifactKind.RUFF_CACHE,
        ArtifactKind.PYTHON_VENV,
    }
    is_python = artifact in python_artifacts
    expected_regenerability = (
        RegenerabilityState.REPRODUCIBLE
        if artifact in {
            ArtifactKind.PYCACHE,
            ArtifactKind.PYTEST_CACHE,
            ArtifactKind.MYPY_CACHE,
            ArtifactKind.RUFF_CACHE,
        }
        else RegenerabilityState.UNKNOWN
        if artifact in {ArtifactKind.DIST, ArtifactKind.BUILD}
        else RegenerabilityState.CONDITIONALLY_REPRODUCIBLE
    )
    unknown_cost_artifacts = {
        ArtifactKind.PYTHON_VENV,
        ArtifactKind.NODE_MODULES,
        ArtifactKind.DIST,
        ArtifactKind.BUILD,
        ArtifactKind.NEXT_BUILD,
    }
    expected = ExpectedDomainInterpretation(
        provenance=Provenance(
            ecosystem="python" if is_python else "node",
            generator="synthetic-generator",
            confidence=Confidence.HIGH,
        ),
        regenerability=expected_regenerability,
        regeneration_cost=(
            RegenerationCost.UNKNOWN
            if artifact in unknown_cost_artifacts
            else RegenerationCost.LOW
        ),
        reachability=ReachabilityState.CONFIRMED_UNREFERENCED,
        activity=ActivityState.INACTIVE,
        protection=ProtectionClass.ORDINARY,
        reclaim_priority=ReclaimPriority.UNKNOWN,
    )
    return SyntheticArtifactFixture(
        fixture_id=f"normal_{artifact.value}",
        artifact=artifact,
        synthetic_path=f"synthetic/{'python' if is_python else 'node'}/{artifact.value}",
        description="Normal synthetic raw observations with complete high-confidence contract evidence.",
        observations=tuple(observations),
        expected_interpretation=expected,
    )


def _replace_observation(
    fixture: SyntheticArtifactFixture,
    key: str,
    *replacement: Evidence,
) -> SyntheticArtifactFixture:
    observations = tuple(item for item in fixture.observations if item.key != key) + replacement
    return replace(fixture, observations=observations)


def initial_artifact_fixtures() -> tuple[SyntheticArtifactFixture, ...]:
    normal = [_normal_fixture(artifact) for artifact in ArtifactKind]

    weak_pycache = replace(
        _replace_observation(
            normal[0],
            "python_bytecode_marker",
            _evidence(
                "python_bytecode_marker",
                "Synthetic marker inferred from a weak signal.",
                confidence=Confidence.LOW,
            ),
        ),
        fixture_id="adversarial_weak_pycache_evidence",
        description="Artifact marker exists only with LOW confidence.",
        expected_interpretation=None,
        adversarial=True,
    )

    missing_venv_metadata = replace(
        _replace_observation(normal[4], "project_metadata_observation"),
        fixture_id="adversarial_venv_missing_project_metadata",
        description="pyvenv.cfg is present but project metadata is missing.",
        expected_interpretation=None,
        adversarial=True,
    )

    corrupt_lockfile = replace(
        normal[5],
        fixture_id="adversarial_node_modules_corrupt_lockfile",
        description="Dependency tree is present but lockfile parsing failed.",
        observations=normal[5].observations + (
            _evidence(
                "lockfile_parse_observation",
                "Synthetic corrupt lockfile parse failure.",
                status=ObservationStatus.FAILED,
                polarity=EvidencePolarity.UNKNOWN,
                confidence=Confidence.UNKNOWN,
            ),
        ),
        expected_interpretation=None,
        adversarial=True,
    )

    conflicting_reachability = replace(
        normal[0],
        fixture_id="adversarial_conflicting_reachability",
        description="One raw observation supports use while another confirms absence.",
        observations=tuple(
            item for item in normal[0].observations if item.key != "reference_check_observation"
        ) + (
            _evidence(
                "reference_check_observation",
                "Synthetic reference was observed through one path.",
                value="reference observed",
            ),
            _evidence(
                "reference_check_observation",
                "Synthetic active check confirmed no references through another path.",
                status=ObservationStatus.CONFIRMED_ABSENT,
                polarity=EvidencePolarity.CONTRADICTS,
                value="no references confirmed",
            ),
        ),
        expected_interpretation=None,
        adversarial=True,
    )

    assumed_absence = replace(
        _replace_observation(
            normal[0],
            "reference_check_observation",
            _evidence(
                "reference_check_observation",
                "Reference was not observed; no active absence check ran.",
                status=ObservationStatus.NOT_OBSERVED,
                polarity=EvidencePolarity.UNKNOWN,
            ),
        ),
        fixture_id="adversarial_assumed_absence",
        description="No reference was found by observation, but absence was not confirmed.",
        expected_interpretation=None,
        adversarial=True,
    )

    confirmed_absence = replace(
        normal[0],
        fixture_id="confirmed_absence",
        description="Reference absence was established by an explicit synthetic check.",
    )

    symlink_base = _replace_observation(
        normal[5],
        "reference_check_observation",
        _evidence(
            "reference_check_observation",
            "Symlink target could not be resolved for reference checking.",
            status=ObservationStatus.UNKNOWN,
            polarity=EvidencePolarity.UNKNOWN,
        ),
    )
    symlink_ambiguity = replace(
        symlink_base,
        fixture_id="adversarial_symlink_reference_ambiguity",
        description="A synthetic symlink may reference another project; target resolution is unknown.",
        synthetic_path="synthetic/node/node_modules-link",
        observed_node_kind=NodeKind.SYMLINK,
        observations=symlink_base.observations + (
            _evidence(
                "reference_resolution_observation",
                "Synthetic symlink target could not be resolved.",
                status=ObservationStatus.UNKNOWN,
                polarity=EvidencePolarity.UNKNOWN,
                confidence=Confidence.UNKNOWN,
            ),
        ),
        expected_interpretation=None,
        adversarial=True,
    )

    return tuple(normal) + (
        weak_pycache,
        missing_venv_metadata,
        corrupt_lockfile,
        conflicting_reachability,
        assumed_absence,
        confirmed_absence,
        symlink_ambiguity,
    )


def fixture_by_id(fixture_id: str) -> SyntheticArtifactFixture:
    for fixture in initial_artifact_fixtures():
        if fixture.fixture_id == fixture_id:
            return fixture
    raise KeyError(fixture_id)
