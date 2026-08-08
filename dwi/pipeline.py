"""Candidate selection and Safety Policy integration for one analysis result."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from .contracts import ArtifactKind
from .dispatcher import AnalysisResult, Interpretation
from .domain import (
    ActionEligibility,
    CleanupCandidate,
    Confidence,
    EvidenceBundle,
    NodeKind,
    ProtectionClass,
    RiskLabel,
)
from .policy import SafetyContext, SafetyDecision, evaluate_safety
from .size import SizeObservation


class CandidateEligibility(str, Enum):
    SELECTED = "selected"
    REJECTED = "rejected"


@dataclass(frozen=True)
class CandidateSelection:
    eligibility: CandidateEligibility
    evidence: EvidenceBundle
    candidate: CleanupCandidate | None
    reason: str | None = None


@dataclass(frozen=True)
class Finding:
    """Auditable result for one discovered supported artifact candidate."""

    artifact: ArtifactKind
    path: str
    evidence: EvidenceBundle
    interpretation: Interpretation
    candidate_selection: CandidateSelection
    safety_decision: SafetyDecision | None
    size: SizeObservation

    @property
    def risk_label(self) -> RiskLabel:
        if self.safety_decision is not None:
            return self.safety_decision.risk_label
        return RiskLabel.REVIEW_REQUIRED

    @property
    def action_eligibility(self) -> ActionEligibility:
        if self.safety_decision is not None:
            return self.safety_decision.action_eligibility
        return ActionEligibility.REQUIRES_REVIEW

    @property
    def rule_trace(self):
        return self.safety_decision.rule_trace if self.safety_decision is not None else None

    @property
    def summary(self) -> str:
        if self.candidate_selection.eligibility is CandidateEligibility.REJECTED:
            return f"Candidate rejected: {self.candidate_selection.reason}"
        assert self.safety_decision is not None
        return (
            f"Risk {self.safety_decision.risk_label.value}; "
            f"action {self.safety_decision.action_eligibility.value}."
        )


def select_candidate(result: AnalysisResult) -> CandidateSelection:
    """Admit only high-confidence artifact identity to the policy boundary."""

    evidence = result.detection.evidence
    node = result.detection.node
    provenance = result.interpretation.provenance

    if node.is_git_metadata:
        return CandidateSelection(
            CandidateEligibility.REJECTED,
            evidence,
            None,
            "Git metadata is protection/context only and never a cleanup candidate.",
        )
    if node.kind is not NodeKind.DIRECTORY:
        return CandidateSelection(
            CandidateEligibility.REJECTED,
            evidence,
            None,
            "The supported artifact path is not an ordinary directory.",
        )
    if node.protection is ProtectionClass.REPOSITORY_PROTECTED:
        return CandidateSelection(
            CandidateEligibility.REJECTED,
            evidence,
            None,
            "Protected filesystem context is not admitted to the cleanup-candidate boundary.",
        )
    if provenance is None or not provenance.meets_confidence(Confidence.HIGH):
        return CandidateSelection(
            CandidateEligibility.REJECTED,
            evidence,
            None,
            "Artifact identity lacks sufficient evidence for candidate selection.",
        )

    candidate = CleanupCandidate(node=node, selection_evidence=evidence)
    return CandidateSelection(CandidateEligibility.SELECTED, evidence, candidate)


def evaluate_analysis(
    result: AnalysisResult,
    *,
    size: SizeObservation | None = None,
    engine_version: str = "dwi-domain-0.1",
) -> Finding:
    """Select and, when admitted, evaluate one analysis result with Safety Policy."""

    selection = select_candidate(result)
    size_observation = size or SizeObservation.unknown()
    if selection.candidate is None:
        return Finding(
            artifact=result.artifact,
            path=result.detection.node.path,
            evidence=result.detection.evidence,
            interpretation=result.interpretation,
            candidate_selection=selection,
            safety_decision=None,
            size=size_observation,
        )

    interpretation = result.interpretation
    decision = evaluate_safety(
        SafetyContext(
            candidate=selection.candidate,
            evidence=result.detection.evidence,
            provenance=interpretation.provenance,
            regenerability=interpretation.regenerability,
            regeneration_cost=interpretation.regeneration_cost,
            reachability=interpretation.reachability,
            activity=interpretation.activity,
            protection=interpretation.protection,
            reclaim_priority=interpretation.reclaim_priority,
        ),
        engine_version=engine_version,
    )
    return Finding(
        artifact=result.artifact,
        path=result.detection.node.path,
        evidence=result.detection.evidence,
        interpretation=result.interpretation,
        candidate_selection=selection,
        safety_decision=decision,
        size=size_observation,
    )
