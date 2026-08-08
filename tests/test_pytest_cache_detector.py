import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from dwi import (
    Confidence,
    Evidence,
    EvidencePolarity,
    NodeKind,
    ObservationStatus,
    ProtectionClass,
    ReachabilityState,
    RegenerabilityState,
    inspect_pytest_cache,
    interpret_pytest_cache,
)


CACHEDIR_TAG = "Signature: 8a477f597d28d172789f06886806bc55\n"
PYTEST_README = "This directory is used by pytest to store cache data.\n"


def _evidence_for(detection, key: str):
    return [item for item in detection.observations if item.key == key]


def _write_valid_cache(cache: Path) -> None:
    cache.mkdir()
    (cache / "CACHEDIR.TAG").write_text(CACHEDIR_TAG, encoding="utf-8")
    (cache / "README.md").write_text(PYTEST_README, encoding="utf-8")
    (cache / "v").mkdir()


class PytestCacheDetectorTests(unittest.TestCase):
    def test_valid_pytest_cache_produces_raw_evidence_and_interpretation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            cache = Path(temporary_directory) / ".pytest_cache"
            _write_valid_cache(cache)

            detection = inspect_pytest_cache(cache)
            assessment = detection.contract_assessment()
            interpretation = interpret_pytest_cache(detection)

            self.assertEqual(detection.node.kind, NodeKind.DIRECTORY)
            self.assertEqual(
                _evidence_for(detection, "pytest_cache_directory_name_observation")[0].confidence,
                Confidence.HIGH,
            )
            self.assertEqual(
                _evidence_for(detection, "pytest_cache_marker")[0].observation_status,
                ObservationStatus.OBSERVED,
            )
            self.assertFalse(assessment.evidence_sufficient)
            self.assertEqual(
                _evidence_for(
                    detection,
                    "recreation_input_availability_observation",
                )[0].observation_status,
                ObservationStatus.UNKNOWN,
            )
            self.assertIsNotNone(interpretation.provenance)
            self.assertEqual(interpretation.provenance.generator, "pytest")
            self.assertEqual(
                interpretation.regenerability,
                RegenerabilityState.CONDITIONALLY_REPRODUCIBLE,
            )
            self.assertEqual(interpretation.reachability, ReachabilityState.UNKNOWN)
            self.assertEqual(interpretation.protection, ProtectionClass.UNKNOWN)
            self.assertFalse(hasattr(interpretation, "risk_label"))

    def test_name_only_match_does_not_establish_pytest_cache_identity(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            cache = Path(temporary_directory) / ".pytest_cache"
            cache.mkdir()
            (cache / "notes.txt").write_text("unrelated", encoding="utf-8")

            detection = inspect_pytest_cache(cache)
            interpretation = interpret_pytest_cache(detection)

            self.assertEqual(
                _evidence_for(detection, "pytest_cache_directory_name_observation")[0].polarity,
                EvidencePolarity.SUPPORTS,
            )
            self.assertEqual(
                _evidence_for(detection, "pytest_cache_marker")[0].observation_status,
                ObservationStatus.CONFIRMED_ABSENT,
            )
            self.assertIsNone(interpretation.provenance)

    def test_empty_directory_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            cache = Path(temporary_directory) / ".pytest_cache"
            cache.mkdir()

            detection = inspect_pytest_cache(cache)

            self.assertEqual(
                _evidence_for(detection, "cache_layout_observation")[0].observation_status,
                ObservationStatus.CONFIRMED_ABSENT,
            )
            self.assertFalse(detection.contract_assessment().evidence_sufficient)

    def test_missing_or_corrupt_marker_is_observation_failure(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            cache = Path(temporary_directory) / ".pytest_cache"
            cache.mkdir()
            (cache / "CACHEDIR.TAG").write_text("", encoding="utf-8")

            detection = inspect_pytest_cache(cache)

            self.assertEqual(
                _evidence_for(detection, "pytest_cache_marker")[0].observation_status,
                ObservationStatus.FAILED,
            )
            self.assertTrue(detection.contract_assessment().has_uncertainty)
            self.assertIsNone(interpret_pytest_cache(detection).provenance)

    def test_unexpected_contents_are_not_treated_as_cache_layout(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            cache = Path(temporary_directory) / ".pytest_cache"
            nested = cache / "nested"
            nested.mkdir(parents=True)
            (cache / "random.txt").write_text("not pytest", encoding="utf-8")
            (nested / "CACHEDIR.TAG").write_text(CACHEDIR_TAG, encoding="utf-8")

            detection = inspect_pytest_cache(cache)

            self.assertEqual(
                _evidence_for(detection, "pytest_cache_marker")[0].observation_status,
                ObservationStatus.CONFIRMED_ABSENT,
            )
            self.assertIsNone(interpret_pytest_cache(detection).provenance)

    def test_unreadable_marker_entry_fails_without_guessing(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            cache = Path(temporary_directory) / ".pytest_cache"
            cache.mkdir()
            (cache / "CACHEDIR.TAG").mkdir()

            detection = inspect_pytest_cache(cache)

            self.assertEqual(
                _evidence_for(detection, "pytest_cache_marker")[0].observation_status,
                ObservationStatus.FAILED,
            )
            self.assertTrue(detection.contract_assessment().has_uncertainty)

    def test_weak_marker_evidence_fails_minimum_confidence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            cache = Path(temporary_directory) / ".pytest_cache"
            cache.mkdir()
            (cache / "CACHEDIR.TAG").write_text("not the standard signature\n", encoding="utf-8")

            detection = inspect_pytest_cache(cache)
            assessment = detection.contract_assessment()

            self.assertIn("pytest_cache_marker", assessment.confidence_shortfalls)
            self.assertFalse(assessment.evidence_sufficient)
            self.assertIsNone(interpret_pytest_cache(detection).provenance)

    def test_conflicting_marker_evidence_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            cache = Path(temporary_directory) / ".pytest_cache"
            _write_valid_cache(cache)
            detection = inspect_pytest_cache(cache)
            conflicting = replace(
                detection,
                observations=detection.observations
                + (
                    Evidence(
                        key="pytest_cache_marker",
                        source="synthetic-test",
                        description="A synthetic marker contradiction.",
                        observation_status=ObservationStatus.CONFIRMED_ABSENT,
                        polarity=EvidencePolarity.CONTRADICTS,
                        confidence=Confidence.HIGH,
                    ),
                ),
            )

            self.assertTrue(conflicting.contract_assessment().has_conflicts)
            self.assertEqual(
                interpret_pytest_cache(conflicting).regenerability,
                RegenerabilityState.CONFLICTING,
            )

    def test_repeated_evaluation_is_deterministic(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            cache = Path(temporary_directory) / ".pytest_cache"
            _write_valid_cache(cache)

            first = inspect_pytest_cache(cache)
            second = inspect_pytest_cache(cache)

            self.assertEqual(first, second)
            self.assertEqual(
                interpret_pytest_cache(first),
                interpret_pytest_cache(second),
            )


if __name__ == "__main__":
    unittest.main()
