import importlib.util
import marshal
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from dwi import (
    ActionEligibility,
    ActivityState,
    CleanupCandidate,
    Confidence,
    Evidence,
    EvidenceBundle,
    EvidencePolarity,
    NodeKind,
    ObservationStatus,
    ProtectionClass,
    ReachabilityState,
    RegenerabilityState,
    RegenerationCost,
    RiskLabel,
    SafetyContext,
    evaluate_safety,
    inspect_pycache,
    interpret_pycache,
)


def _write_valid_pyc(path: Path, *, source_name: str = "module.py") -> None:
    code = compile("value = 1\n", source_name, "exec")
    header = (
        importlib.util.MAGIC_NUMBER
        + (0).to_bytes(4, "little")
        + (0).to_bytes(4, "little")
        + (0).to_bytes(4, "little")
    )
    path.write_bytes(header + marshal.dumps(code))


def _evidence_for(detection, key: str):
    return [item for item in detection.observations if item.key == key]


class PycacheDetectorTests(unittest.TestCase):
    def test_valid_pycache_produces_raw_evidence_and_separate_interpretation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            cache = Path(temporary_directory) / "__pycache__"
            cache.mkdir()
            _write_valid_pyc(cache / "module.cpython-313.pyc")

            detection = inspect_pycache(cache)
            assessment = detection.contract_assessment()
            interpretation = interpret_pycache(detection)

            self.assertEqual(detection.node.kind, NodeKind.DIRECTORY)
            self.assertEqual(
                _evidence_for(detection, "pycache_directory_name_observation")[0].confidence,
                Confidence.HIGH,
            )
            self.assertEqual(
                _evidence_for(detection, "python_bytecode_marker")[0].observation_status,
                ObservationStatus.OBSERVED,
            )
            self.assertEqual(
                _evidence_for(detection, "python_source_reference_observation")[0].observation_status,
                ObservationStatus.OBSERVED,
            )
            self.assertEqual(
                _evidence_for(
                    detection,
                    "recreation_input_availability_observation",
                )[0].observation_status,
                ObservationStatus.UNKNOWN,
            )
            self.assertFalse(assessment.evidence_sufficient)
            self.assertIn("reference_check_observation", assessment.confidence_shortfalls)
            self.assertIsNotNone(interpretation.provenance)
            self.assertEqual(interpretation.regenerability, RegenerabilityState.CONDITIONALLY_REPRODUCIBLE)
            self.assertEqual(interpretation.regeneration_cost, RegenerationCost.LOW)
            self.assertEqual(interpretation.reachability, ReachabilityState.UNKNOWN)
            self.assertEqual(interpretation.activity, ActivityState.UNKNOWN)
            self.assertEqual(interpretation.protection, ProtectionClass.UNKNOWN)
            self.assertFalse(hasattr(interpretation, "risk_label"))

    def test_valid_structure_still_fails_policy_closed_for_unknown_context(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            cache = Path(temporary_directory) / "__pycache__"
            cache.mkdir()
            _write_valid_pyc(cache / "module.pyc")
            detection = inspect_pycache(cache)
            interpretation = interpret_pycache(detection)
            candidate = CleanupCandidate(
                node=detection.node,
                selection_evidence=EvidenceBundle(
                    observations=(
                        Evidence(
                            key="candidate_identity",
                            source="synthetic-test",
                            description="Synthetic pycache candidate boundary evidence.",
                            observation_status=ObservationStatus.OBSERVED,
                            polarity=EvidencePolarity.SUPPORTS,
                            confidence=Confidence.HIGH,
                        ),
                    )
                ),
            )

            decision = evaluate_safety(
                SafetyContext(
                    candidate=candidate,
                    evidence=detection.evidence,
                    provenance=interpretation.provenance,
                    regenerability=interpretation.regenerability,
                    regeneration_cost=interpretation.regeneration_cost,
                    reachability=interpretation.reachability,
                    activity=interpretation.activity,
                    protection=interpretation.protection,
                )
            )

            self.assertEqual(decision.risk_label, RiskLabel.REVIEW_REQUIRED)
            self.assertEqual(decision.action_eligibility, ActionEligibility.REQUIRES_REVIEW)

    def test_name_match_without_structural_evidence_is_not_interpreted(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            cache = Path(temporary_directory) / "__pycache__"
            cache.mkdir()
            (cache / "README.md").write_text("not bytecode", encoding="utf-8")

            detection = inspect_pycache(cache)
            interpretation = interpret_pycache(detection)

            self.assertEqual(
                _evidence_for(detection, "pycache_directory_name_observation")[0].polarity,
                EvidencePolarity.SUPPORTS,
            )
            self.assertEqual(
                _evidence_for(detection, "python_bytecode_marker")[0].observation_status,
                ObservationStatus.CONFIRMED_ABSENT,
            )
            self.assertIsNone(interpretation.provenance)
            self.assertEqual(interpretation.regenerability, RegenerabilityState.UNKNOWN)

    def test_empty_pycache_is_distinct_from_confirmed_bytecode_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            cache = Path(temporary_directory) / "__pycache__"
            cache.mkdir()

            detection = inspect_pycache(cache)

            self.assertEqual(
                _evidence_for(detection, "metadata_readability_observation")[0].observation_status,
                ObservationStatus.OBSERVED,
            )
            self.assertEqual(
                _evidence_for(detection, "python_bytecode_marker")[0].observation_status,
                ObservationStatus.CONFIRMED_ABSENT,
            )
            self.assertEqual(
                _evidence_for(detection, "python_source_reference_observation")[0].observation_status,
                ObservationStatus.NOT_OBSERVED,
            )

    def test_unexpected_and_nested_contents_are_not_scanned_as_pycache(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            cache = Path(temporary_directory) / "__pycache__"
            nested = cache / "nested"
            nested.mkdir(parents=True)
            (cache / "module.py").write_text("value = 1", encoding="utf-8")
            _write_valid_pyc(nested / "module.pyc")

            detection = inspect_pycache(cache)

            self.assertEqual(
                _evidence_for(detection, "python_bytecode_marker")[0].observation_status,
                ObservationStatus.CONFIRMED_ABSENT,
            )
            self.assertIsNone(interpret_pycache(detection).provenance)

    def test_weak_bytecode_signal_fails_minimum_confidence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            cache = Path(temporary_directory) / "__pycache__"
            cache.mkdir()
            (cache / "module.pyc").write_bytes(importlib.util.MAGIC_NUMBER)

            detection = inspect_pycache(cache)
            assessment = detection.contract_assessment()

            self.assertIn("python_bytecode_marker", assessment.confidence_shortfalls)
            self.assertFalse(assessment.evidence_sufficient)
            self.assertIsNone(interpret_pycache(detection).provenance)

    def test_observation_failure_is_recorded_without_guessing(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            cache = Path(temporary_directory) / "__pycache__"
            cache.mkdir()
            (cache / "module.pyc").mkdir()

            detection = inspect_pycache(cache)
            marker = _evidence_for(detection, "python_bytecode_marker")

            self.assertEqual(marker[0].observation_status, ObservationStatus.FAILED)
            self.assertTrue(detection.contract_assessment().has_uncertainty)
            self.assertIsNone(interpret_pycache(detection).provenance)

    def test_conflicting_reference_evidence_fails_closed_in_interpretation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            cache = Path(temporary_directory) / "__pycache__"
            cache.mkdir()
            _write_valid_pyc(cache / "module.pyc")
            detection = inspect_pycache(cache)
            conflicting = replace(
                detection,
                observations=detection.observations
                + (
                    Evidence(
                        key="reference_check_observation",
                        source="synthetic-test",
                        description="A synthetic reference was observed.",
                        observation_status=ObservationStatus.OBSERVED,
                        polarity=EvidencePolarity.SUPPORTS,
                        confidence=Confidence.HIGH,
                    ),
                    Evidence(
                        key="reference_check_observation",
                        source="synthetic-test",
                        description="A separate check confirmed no reference.",
                        observation_status=ObservationStatus.CONFIRMED_ABSENT,
                        polarity=EvidencePolarity.CONTRADICTS,
                        confidence=Confidence.HIGH,
                    ),
                ),
            )

            self.assertTrue(conflicting.contract_assessment().has_conflicts)
            self.assertEqual(
                interpret_pycache(conflicting).reachability,
                ReachabilityState.CONFLICTING,
            )

    def test_confirmed_reference_maps_to_hard_gate_state(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            cache = Path(temporary_directory) / "__pycache__"
            cache.mkdir()
            _write_valid_pyc(cache / "module.pyc")
            detection = inspect_pycache(cache)
            referenced = replace(
                detection,
                observations=tuple(
                    item
                    for item in detection.observations
                    if item.key != "reference_check_observation"
                )
                + (
                    Evidence(
                        key="reference_check_observation",
                        source="synthetic-test",
                        description="A synthetic active consumer reference was confirmed.",
                        observation_status=ObservationStatus.OBSERVED,
                        polarity=EvidencePolarity.SUPPORTS,
                        confidence=Confidence.HIGH,
                    ),
                ),
            )
            interpretation = interpret_pycache(referenced)

            self.assertEqual(
                interpretation.reachability,
                ReachabilityState.CONFIRMED_REFERENCED,
            )

            candidate = CleanupCandidate(
                node=referenced.node,
                selection_evidence=EvidenceBundle(
                    observations=(
                        Evidence(
                            key="candidate_identity",
                            source="synthetic-test",
                            description="Synthetic pycache candidate boundary evidence.",
                            observation_status=ObservationStatus.OBSERVED,
                            polarity=EvidencePolarity.SUPPORTS,
                            confidence=Confidence.HIGH,
                        ),
                    )
                ),
            )
            decision = evaluate_safety(
                SafetyContext(
                    candidate=candidate,
                    evidence=referenced.evidence,
                    provenance=interpretation.provenance,
                    regenerability=interpretation.regenerability,
                    regeneration_cost=interpretation.regeneration_cost,
                    reachability=interpretation.reachability,
                    activity=interpretation.activity,
                    protection=interpretation.protection,
                )
            )
            self.assertEqual(decision.risk_label, RiskLabel.REVIEW_REQUIRED)
            self.assertNotEqual(decision.risk_label, RiskLabel.REGENERATABLE)

    def test_repeated_evaluation_is_deterministic(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            cache = Path(temporary_directory) / "__pycache__"
            cache.mkdir()
            _write_valid_pyc(cache / "module.pyc")

            first = inspect_pycache(cache)
            second = inspect_pycache(cache)

            self.assertEqual(first, second)
            self.assertEqual(interpret_pycache(first), interpret_pycache(second))


if __name__ == "__main__":
    unittest.main()
