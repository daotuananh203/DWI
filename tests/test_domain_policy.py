import unittest
from dataclasses import FrozenInstanceError

from dwi import (
    ActionEligibility,
    ActivityState,
    CleanupCandidate,
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
    RiskLabel,
    SafetyContext,
    evaluate_safety,
    escalate_risk,
)


REQUIRED_KEYS = frozenset(
    {
        "artifact_identity",
        "provenance",
        "regenerability",
        "reachability",
        "activity",
        "protection",
    }
)


def evidence_bundle(*, replacement: Evidence | None = None, extra: tuple[Evidence, ...] = ()) -> EvidenceBundle:
    observations = [
        Evidence(
            key=key,
            source="synthetic-fixture",
            description=f"Synthetic evidence for {key}.",
            observation_status=ObservationStatus.OBSERVED,
            polarity=EvidencePolarity.SUPPORTS,
            confidence=Confidence.HIGH,
        )
        for key in sorted(REQUIRED_KEYS)
    ]
    if replacement is not None:
        observations = [item for item in observations if item.key != replacement.key]
        observations.append(replacement)
    observations.extend(extra)
    return EvidenceBundle(
        tuple(observations),
        tuple(EvidenceRequirement(key, Confidence.HIGH) for key in sorted(REQUIRED_KEYS)),
    )


def candidate(*, protection: ProtectionClass = ProtectionClass.ORDINARY, kind: NodeKind = NodeKind.DIRECTORY) -> CleanupCandidate:
    node = ObservedNode(path="synthetic/workspace/artifact", kind=kind, protection=protection)
    selection = EvidenceBundle(
        observations=(
            Evidence(
                key="candidate_identity",
                source="synthetic-fixture",
                description="Synthetic candidate-selection evidence.",
                observation_status=ObservationStatus.OBSERVED,
                polarity=EvidencePolarity.SUPPORTS,
                confidence=Confidence.HIGH,
            ),
        )
    )
    return CleanupCandidate(node=node, selection_evidence=selection)


def context(
    *,
    evidence: EvidenceBundle | None = None,
    regenerability: RegenerabilityState = RegenerabilityState.REPRODUCIBLE,
    reachability: ReachabilityState = ReachabilityState.CONFIRMED_UNREFERENCED,
    activity: ActivityState = ActivityState.INACTIVE,
    protection: ProtectionClass = ProtectionClass.ORDINARY,
    established_risk: RiskLabel = RiskLabel.SAFE,
) -> SafetyContext:
    return SafetyContext(
        candidate=candidate(protection=protection),
        evidence=evidence or evidence_bundle(),
        provenance=Provenance("python", "synthetic-generator", Confidence.HIGH),
        regenerability=regenerability,
        regeneration_cost=RegenerationCost.LOW,
        reachability=reachability,
        activity=activity,
        protection=protection,
        reclaim_priority=ReclaimPriority.HIGH,
        established_risk=established_risk,
    )


class DomainAndPolicyTests(unittest.TestCase):
    def test_domain_objects_are_immutable(self) -> None:
        node = ObservedNode("synthetic/node", NodeKind.DIRECTORY, ProtectionClass.ORDINARY)
        with self.assertRaises(FrozenInstanceError):
            node.path = "changed"  # type: ignore[misc]

    def test_git_metadata_is_observed_context_not_cleanup_candidate(self) -> None:
        with self.assertRaises(ValueError):
            candidate(protection=ProtectionClass.REPOSITORY_PROTECTED, kind=NodeKind.GIT_DIRECTORY)
        with self.assertRaises(ValueError):
            candidate(protection=ProtectionClass.REPOSITORY_PROTECTED, kind=NodeKind.GIT_FILE)

    def test_missing_evidence_fails_closed(self) -> None:
        incomplete = EvidenceBundle(
            observations=(),
            requirements=tuple(EvidenceRequirement(key, Confidence.HIGH) for key in sorted(REQUIRED_KEYS)),
        )
        decision = evaluate_safety(context(evidence=incomplete))
        self.assertEqual(decision.risk_label, RiskLabel.REVIEW_REQUIRED)
        self.assertEqual(decision.action_eligibility, ActionEligibility.REQUIRES_REVIEW)

    def test_failed_evidence_fails_closed(self) -> None:
        failed = Evidence(
            key="reachability",
            source="synthetic-fixture",
            description="Synthetic permission failure.",
            observation_status=ObservationStatus.FAILED,
            polarity=EvidencePolarity.UNKNOWN,
            confidence=Confidence.UNKNOWN,
        )
        decision = evaluate_safety(context(evidence=evidence_bundle(replacement=failed)))
        self.assertEqual(decision.risk_label, RiskLabel.REVIEW_REQUIRED)

    def test_unknown_evidence_certainty_fails_closed(self) -> None:
        uncertain = Evidence(
            key="activity",
            source="synthetic-fixture",
            description="Synthetic evidence with unknown confidence.",
            observation_status=ObservationStatus.OBSERVED,
            polarity=EvidencePolarity.SUPPORTS,
            confidence=Confidence.UNKNOWN,
        )
        decision = evaluate_safety(context(evidence=evidence_bundle(replacement=uncertain)))
        self.assertEqual(decision.risk_label, RiskLabel.REVIEW_REQUIRED)

    def test_not_observed_is_not_confirmed_absence(self) -> None:
        not_found = Evidence(
            key="reachability",
            source="synthetic-fixture",
            description="The reference was not observed, but no active absence check ran.",
            observation_status=ObservationStatus.NOT_OBSERVED,
            polarity=EvidencePolarity.UNKNOWN,
            confidence=Confidence.HIGH,
        )
        decision = evaluate_safety(context(evidence=evidence_bundle(replacement=not_found)))
        self.assertEqual(decision.risk_label, RiskLabel.REVIEW_REQUIRED)
        with self.assertRaises(ValueError):
            Evidence(
                key="reachability",
                source="synthetic-fixture",
                description="Invalid negative evidence based only on non-observation.",
                observation_status=ObservationStatus.NOT_OBSERVED,
                polarity=EvidencePolarity.CONTRADICTS,
                confidence=Confidence.HIGH,
            )

    def test_confirmed_absence_requires_active_check_and_is_distinct(self) -> None:
        confirmed_absence = Evidence(
            key="reachability",
            source="synthetic-fixture",
            description="Synthetic active check confirmed no references.",
            observation_status=ObservationStatus.CONFIRMED_ABSENT,
            polarity=EvidencePolarity.CONTRADICTS,
            confidence=Confidence.HIGH,
        )
        bundle = evidence_bundle(replacement=confirmed_absence)
        self.assertFalse(bundle.has_uncertainty)
        self.assertFalse(bundle.confidence_shortfalls)

    def test_low_confidence_does_not_meet_default_strong_requirement(self) -> None:
        low = Evidence(
            key="provenance",
            source="synthetic-fixture",
            description="Synthetic low-confidence provenance.",
            observation_status=ObservationStatus.OBSERVED,
            polarity=EvidencePolarity.SUPPORTS,
            confidence=Confidence.LOW,
        )
        bundle = evidence_bundle(replacement=low)
        self.assertIn("provenance", bundle.confidence_shortfalls)
        decision = evaluate_safety(context(evidence=bundle))
        self.assertEqual(decision.risk_label, RiskLabel.REVIEW_REQUIRED)

    def test_evidence_requirement_expresses_minimum_confidence(self) -> None:
        requirement = EvidenceRequirement("activity", Confidence.MEDIUM)
        medium = Evidence(
            key="activity",
            source="synthetic-fixture",
            description="Synthetic medium-confidence activity evidence.",
            observation_status=ObservationStatus.OBSERVED,
            polarity=EvidencePolarity.SUPPORTS,
            confidence=Confidence.MEDIUM,
        )
        bundle = EvidenceBundle((medium,), (requirement,))
        self.assertTrue(bundle.is_complete)
        self.assertFalse(bundle.confidence_shortfalls)

    def test_conflicting_evidence_fails_closed(self) -> None:
        conflict = Evidence(
            key="reachability",
            source="synthetic-fixture",
            description="Synthetic conflicting reference evidence.",
            observation_status=ObservationStatus.OBSERVED,
            polarity=EvidencePolarity.CONFLICTING,
            confidence=Confidence.HIGH,
        )
        decision = evaluate_safety(context(evidence=evidence_bundle(replacement=conflict)))
        self.assertEqual(decision.risk_label, RiskLabel.REVIEW_REQUIRED)

    def test_confirmed_reference_blocks_safe_and_regeneratable(self) -> None:
        decision = evaluate_safety(context(reachability=ReachabilityState.CONFIRMED_REFERENCED))
        self.assertEqual(decision.risk_label, RiskLabel.REVIEW_REQUIRED)
        self.assertNotEqual(decision.risk_label, RiskLabel.SAFE)
        self.assertNotEqual(decision.risk_label, RiskLabel.REGENERATABLE)

    def test_regenerability_state_is_not_the_risk_label(self) -> None:
        decision = evaluate_safety(
            context(
                regenerability=RegenerabilityState.REPRODUCIBLE,
                activity=ActivityState.UNKNOWN,
            )
        )
        self.assertEqual(decision.regenerability, RegenerabilityState.REPRODUCIBLE)
        self.assertEqual(decision.risk_label, RiskLabel.REVIEW_REQUIRED)

    def test_active_runtime_escalates_risk_and_blocks_action(self) -> None:
        decision = evaluate_safety(context(activity=ActivityState.ACTIVE_RUNTIME))
        self.assertEqual(decision.risk_label, RiskLabel.REVIEW_REQUIRED)
        self.assertEqual(decision.activity, ActivityState.ACTIVE_RUNTIME)
        self.assertEqual(decision.action_eligibility, ActionEligibility.BLOCKED)

    def test_monotonic_risk_escalation(self) -> None:
        labels = list(RiskLabel)
        for current in labels:
            for proposed in labels:
                result = escalate_risk(current, proposed)
                self.assertGreaterEqual(result.rank, current.rank)
                self.assertGreaterEqual(result.rank, proposed.rank)

        decision = evaluate_safety(context(established_risk=RiskLabel.REVIEW_REQUIRED))
        self.assertEqual(decision.risk_label, RiskLabel.REVIEW_REQUIRED)

    def test_separate_state_dimensions_are_preserved(self) -> None:
        decision = evaluate_safety(
            context(
                regenerability=RegenerabilityState.CONDITIONALLY_REPRODUCIBLE,
                reachability=ReachabilityState.CONFIRMED_UNREFERENCED,
                activity=ActivityState.INACTIVE,
                protection=ProtectionClass.ORDINARY,
            )
        )
        self.assertEqual(decision.regenerability, RegenerabilityState.CONDITIONALLY_REPRODUCIBLE)
        self.assertEqual(decision.reachability, ReachabilityState.CONFIRMED_UNREFERENCED)
        self.assertEqual(decision.activity, ActivityState.INACTIVE)
        self.assertEqual(decision.protection, ProtectionClass.ORDINARY)
        self.assertEqual(decision.reclaim_priority, ReclaimPriority.HIGH)
        self.assertIsNotNone(decision.rule_trace)


if __name__ == "__main__":
    unittest.main()
