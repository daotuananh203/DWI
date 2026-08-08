import json
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
    inspect_mypy_cache,
    interpret_mypy_cache,
)


def _evidence_for(detection, key: str):
    return [item for item in detection.observations if item.key == key]


def _write_valid_cache(cache: Path) -> None:
    module_directory = cache / "3.11" / "app"
    module_directory.mkdir(parents=True)
    (module_directory / "__init__.meta.json").write_text(
        json.dumps({"id": "app", "version_id": "1.0"}),
        encoding="utf-8",
    )
    (module_directory / "__init__.data.json").write_text(
        json.dumps({"names": {}}),
        encoding="utf-8",
    )


class MypyCacheDetectorTests(unittest.TestCase):
    def test_valid_mypy_cache_produces_raw_evidence_and_interpretation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            cache = Path(temporary_directory) / ".mypy_cache"
            _write_valid_cache(cache)

            detection = inspect_mypy_cache(cache)
            assessment = detection.contract_assessment()
            interpretation = interpret_mypy_cache(detection)

            self.assertEqual(detection.node.kind, NodeKind.DIRECTORY)
            self.assertEqual(
                _evidence_for(detection, "mypy_cache_directory_name_observation")[0].confidence,
                Confidence.HIGH,
            )
            self.assertEqual(
                _evidence_for(detection, "mypy_cache_marker")[0].observation_status,
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
            self.assertEqual(interpretation.provenance.generator, "mypy")
            self.assertEqual(
                interpretation.regenerability,
                RegenerabilityState.CONDITIONALLY_REPRODUCIBLE,
            )
            self.assertEqual(interpretation.regeneration_cost.value, "unknown")
            self.assertEqual(interpretation.reachability, ReachabilityState.UNKNOWN)
            self.assertEqual(interpretation.protection, ProtectionClass.UNKNOWN)
            self.assertFalse(hasattr(interpretation, "risk_label"))

    def test_name_only_match_does_not_establish_mypy_cache_identity(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            cache = Path(temporary_directory) / ".mypy_cache"
            cache.mkdir()
            (cache / "notes.txt").write_text("unrelated", encoding="utf-8")

            detection = inspect_mypy_cache(cache)
            interpretation = interpret_mypy_cache(detection)

            self.assertEqual(
                _evidence_for(detection, "mypy_cache_directory_name_observation")[0].polarity,
                EvidencePolarity.SUPPORTS,
            )
            self.assertEqual(
                _evidence_for(detection, "mypy_cache_marker")[0].observation_status,
                ObservationStatus.CONFIRMED_ABSENT,
            )
            self.assertIsNone(interpretation.provenance)

    def test_empty_directory_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            cache = Path(temporary_directory) / ".mypy_cache"
            cache.mkdir()

            detection = inspect_mypy_cache(cache)

            self.assertEqual(
                _evidence_for(detection, "cache_layout_observation")[0].observation_status,
                ObservationStatus.CONFIRMED_ABSENT,
            )
            self.assertFalse(detection.contract_assessment().evidence_sufficient)

    def test_missing_or_corrupt_structural_pair_is_observation_failure(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            cache = Path(temporary_directory) / ".mypy_cache"
            metadata_directory = cache / "3.11"
            metadata_directory.mkdir(parents=True)
            (metadata_directory / "module.meta.json").write_text("{broken", encoding="utf-8")
            (metadata_directory / "module.data.json").write_text("{}", encoding="utf-8")

            detection = inspect_mypy_cache(cache)

            self.assertEqual(
                _evidence_for(detection, "mypy_cache_marker")[0].observation_status,
                ObservationStatus.FAILED,
            )
            self.assertTrue(detection.contract_assessment().has_uncertainty)
            self.assertIsNone(interpret_mypy_cache(detection).provenance)

    def test_unexpected_contents_are_not_treated_as_mypy_layout(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            cache = Path(temporary_directory) / ".mypy_cache"
            version_directory = cache / "3.11"
            version_directory.mkdir(parents=True)
            (version_directory / "random.txt").write_text("not mypy", encoding="utf-8")
            (cache / "nested").mkdir()
            (cache / "nested" / "module.meta.json").write_text("{}", encoding="utf-8")

            detection = inspect_mypy_cache(cache)

            self.assertEqual(
                _evidence_for(detection, "mypy_cache_marker")[0].confidence,
                Confidence.LOW,
            )
            self.assertIsNone(interpret_mypy_cache(detection).provenance)

    def test_unreadable_structural_entry_fails_without_guessing(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            cache = Path(temporary_directory) / ".mypy_cache"
            version_directory = cache / "3.11"
            version_directory.mkdir(parents=True)
            (version_directory / "module.meta.json").mkdir()
            (version_directory / "module.data.json").write_text("{}", encoding="utf-8")

            detection = inspect_mypy_cache(cache)

            self.assertEqual(
                _evidence_for(detection, "mypy_cache_marker")[0].observation_status,
                ObservationStatus.FAILED,
            )
            self.assertTrue(detection.contract_assessment().has_uncertainty)

    def test_weak_version_directory_signal_fails_minimum_confidence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            cache = Path(temporary_directory) / ".mypy_cache"
            (cache / "3.11").mkdir(parents=True)

            detection = inspect_mypy_cache(cache)
            assessment = detection.contract_assessment()

            self.assertIn("mypy_cache_marker", assessment.confidence_shortfalls)
            self.assertFalse(assessment.evidence_sufficient)
            self.assertIsNone(interpret_mypy_cache(detection).provenance)

    def test_conflicting_marker_evidence_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            cache = Path(temporary_directory) / ".mypy_cache"
            _write_valid_cache(cache)
            detection = inspect_mypy_cache(cache)
            conflicting = replace(
                detection,
                observations=detection.observations
                + (
                    Evidence(
                        key="mypy_cache_marker",
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
                interpret_mypy_cache(conflicting).regenerability,
                RegenerabilityState.CONFLICTING,
            )

    def test_repeated_evaluation_is_deterministic(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            cache = Path(temporary_directory) / ".mypy_cache"
            _write_valid_cache(cache)

            first = inspect_mypy_cache(cache)
            second = inspect_mypy_cache(cache)

            self.assertEqual(first, second)
            self.assertEqual(
                interpret_mypy_cache(first),
                interpret_mypy_cache(second),
            )


if __name__ == "__main__":
    unittest.main()
