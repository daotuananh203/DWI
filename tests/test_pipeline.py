import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from dwi import (
    ActionEligibility,
    CandidateEligibility,
    Confidence,
    Evidence,
    EvidencePolarity,
    ObservationStatus,
    ReachabilityState,
    RiskLabel,
    ProtectionClass,
    analyze_candidate,
    evaluate_analysis,
)


class PipelineTests(unittest.TestCase):
    def test_weak_identity_is_rejected_and_raw_evidence_is_preserved(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory) / "dist"
            path.mkdir()
            result = analyze_candidate(path)
            assert result is not None
            finding = evaluate_analysis(result)
            self.assertEqual(finding.candidate_selection.eligibility, CandidateEligibility.REJECTED)
            self.assertIsNone(finding.safety_decision)
            self.assertEqual(finding.evidence, result.detection.evidence)
            self.assertEqual(finding.risk_label, RiskLabel.REVIEW_REQUIRED)

    def test_unknown_reachability_is_policy_review(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory) / ".pytest_cache"
            path.mkdir()
            (path / "CACHEDIR.TAG").write_text("Signature: 8a477f597d28d172789f06886806bc55\n", encoding="utf-8")
            result = analyze_candidate(path)
            assert result is not None
            finding = evaluate_analysis(result)
            self.assertIsNotNone(finding.safety_decision)
            self.assertEqual(finding.risk_label, RiskLabel.REVIEW_REQUIRED)
            self.assertEqual(finding.action_eligibility, ActionEligibility.REQUIRES_REVIEW)

    def test_confirmed_reference_remains_hard_gate_through_adapter(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory) / ".pytest_cache"
            path.mkdir()
            (path / "CACHEDIR.TAG").write_text("Signature: 8a477f597d28d172789f06886806bc55\n", encoding="utf-8")
            result = analyze_candidate(path)
            assert result is not None
            observations = tuple(item for item in result.detection.observations if item.key != "reference_check_observation") + (
                Evidence(
                    key="reference_check_observation",
                    source="synthetic-test",
                    description="A confirmed synthetic consumer reference.",
                    observation_status=ObservationStatus.OBSERVED,
                    polarity=EvidencePolarity.SUPPORTS,
                    confidence=Confidence.HIGH,
                ),
            )
            detection = replace(result.detection, observations=observations)
            interpretation = replace(result.interpretation, reachability=ReachabilityState.CONFIRMED_REFERENCED)
            finding = evaluate_analysis(replace(result, detection=detection, interpretation=interpretation))
            self.assertEqual(finding.risk_label, RiskLabel.REVIEW_REQUIRED)
            self.assertNotEqual(finding.risk_label, RiskLabel.SAFE)
            self.assertNotEqual(finding.risk_label, RiskLabel.REGENERATABLE)

    def test_active_runtime_blocks_action_without_becoming_cleanup_authorization(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory) / ".pytest_cache"
            path.mkdir()
            (path / "CACHEDIR.TAG").write_text("Signature: 8a477f597d28d172789f06886806bc55\n", encoding="utf-8")
            result = analyze_candidate(path)
            assert result is not None
            finding = evaluate_analysis(result)
            from dwi import ActivityState
            active_finding = evaluate_analysis(replace(result, interpretation=replace(result.interpretation, activity=ActivityState.ACTIVE_RUNTIME)))
            self.assertEqual(active_finding.action_eligibility, ActionEligibility.BLOCKED)

    def test_system_protection_reaches_never_delete_policy_floor(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory) / ".pytest_cache"
            path.mkdir()
            (path / "CACHEDIR.TAG").write_text("Signature: 8a477f597d28d172789f06886806bc55\n", encoding="utf-8")
            result = analyze_candidate(path)
            assert result is not None
            protected_detection = replace(
                result.detection,
                node=replace(result.detection.node, protection=ProtectionClass.SYSTEM_PROTECTED),
            )
            protected_interpretation = replace(result.interpretation, protection=ProtectionClass.SYSTEM_PROTECTED)
            finding = evaluate_analysis(replace(result, detection=protected_detection, interpretation=protected_interpretation))
            self.assertEqual(finding.risk_label, RiskLabel.NEVER_DELETE)
            self.assertEqual(finding.action_eligibility, ActionEligibility.BLOCKED)


if __name__ == "__main__":
    unittest.main()
