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
    inspect_ruff_cache,
    interpret_ruff_cache,
)


CACHEDIR_TAG = "Signature: 8a477f597d28d172789f06886806bc55\n"
RUFF_GITIGNORE = "# Automatically created by ruff.\n*\n"


def _evidence_for(detection, key: str):
    return [item for item in detection.observations if item.key == key]


def _write_valid_cache(cache: Path) -> None:
    version_directory = cache / "0.15.0"
    version_directory.mkdir(parents=True)
    (cache / "CACHEDIR.TAG").write_text(CACHEDIR_TAG, encoding="utf-8")
    (cache / ".gitignore").write_text(RUFF_GITIGNORE, encoding="utf-8")
    (version_directory / "123456789").write_bytes(b"synthetic cache data")


class RuffCacheDetectorTests(unittest.TestCase):
    def test_valid_ruff_cache_produces_raw_evidence_and_interpretation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            cache = Path(temporary_directory) / ".ruff_cache"
            _write_valid_cache(cache)

            detection = inspect_ruff_cache(cache)
            assessment = detection.contract_assessment()
            interpretation = interpret_ruff_cache(detection)

            self.assertEqual(detection.node.kind, NodeKind.DIRECTORY)
            self.assertEqual(
                _evidence_for(detection, "ruff_cache_directory_name_observation")[0].confidence,
                Confidence.HIGH,
            )
            marker_values = {
                item.value
                for item in _evidence_for(detection, "ruff_cache_marker")
                if item.observation_status is ObservationStatus.OBSERVED
            }
            self.assertEqual(marker_values, {"CACHEDIR.TAG", ".gitignore"})
            self.assertFalse(assessment.evidence_sufficient)
            self.assertIsNotNone(interpretation.provenance)
            self.assertEqual(interpretation.provenance.generator, "ruff")
            self.assertEqual(
                interpretation.regenerability,
                RegenerabilityState.CONDITIONALLY_REPRODUCIBLE,
            )
            self.assertEqual(interpretation.reachability, ReachabilityState.UNKNOWN)
            self.assertEqual(interpretation.protection, ProtectionClass.UNKNOWN)
            self.assertFalse(hasattr(interpretation, "risk_label"))

    def test_name_only_match_does_not_establish_ruff_cache_identity(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            cache = Path(temporary_directory) / ".ruff_cache"
            cache.mkdir()
            (cache / "notes.txt").write_text("unrelated", encoding="utf-8")

            detection = inspect_ruff_cache(cache)
            interpretation = interpret_ruff_cache(detection)

            self.assertEqual(
                _evidence_for(detection, "ruff_cache_directory_name_observation")[0].polarity,
                EvidencePolarity.SUPPORTS,
            )
            self.assertEqual(
                _evidence_for(detection, "ruff_cache_marker")[0].observation_status,
                ObservationStatus.CONFIRMED_ABSENT,
            )
            self.assertIsNone(interpretation.provenance)

    def test_empty_directory_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            cache = Path(temporary_directory) / ".ruff_cache"
            cache.mkdir()

            detection = inspect_ruff_cache(cache)

            self.assertEqual(
                _evidence_for(detection, "cache_layout_observation")[0].observation_status,
                ObservationStatus.CONFIRMED_ABSENT,
            )
            self.assertFalse(detection.contract_assessment().evidence_sufficient)

    def test_partial_version_structure_is_weak(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            cache = Path(temporary_directory) / ".ruff_cache"
            cache.mkdir()
            (cache / "0.15.0").mkdir()

            detection = inspect_ruff_cache(cache)
            assessment = detection.contract_assessment()

            self.assertEqual(
                _evidence_for(detection, "cache_layout_observation")[0].confidence,
                Confidence.LOW,
            )
            self.assertIn("cache_layout_observation", assessment.confidence_shortfalls)
            self.assertIsNone(interpret_ruff_cache(detection).provenance)

    def test_corrupt_root_marker_fails_without_guessing(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            cache = Path(temporary_directory) / ".ruff_cache"
            cache.mkdir()
            (cache / "CACHEDIR.TAG").write_text("not the standard marker\n", encoding="utf-8")
            (cache / ".gitignore").write_text(RUFF_GITIGNORE, encoding="utf-8")
            version_directory = cache / "0.15.0"
            version_directory.mkdir()
            (version_directory / "123").write_bytes(b"data")

            detection = inspect_ruff_cache(cache)
            interpretation = interpret_ruff_cache(detection)

            self.assertIn(
                Confidence.LOW,
                {
                    item.confidence
                    for item in _evidence_for(detection, "ruff_cache_marker")
                },
            )
            self.assertIsNone(interpretation.provenance)

    def test_unexpected_contents_are_not_scanned_as_ruff_layout(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            cache = Path(temporary_directory) / ".ruff_cache"
            cache.mkdir()
            (cache / "random-version").mkdir()
            (cache / "random-version" / "CACHEDIR.TAG").write_text(
                CACHEDIR_TAG,
                encoding="utf-8",
            )
            (cache / "nested").mkdir()
            (cache / "nested" / "0.15.0").mkdir()
            (cache / "nested" / "0.15.0" / "123").write_bytes(b"data")

            detection = inspect_ruff_cache(cache)

            self.assertEqual(
                _evidence_for(detection, "ruff_cache_marker")[0].observation_status,
                ObservationStatus.CONFIRMED_ABSENT,
            )
            self.assertIsNone(interpret_ruff_cache(detection).provenance)

    def test_unreadable_marker_entry_fails_without_guessing(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            cache = Path(temporary_directory) / ".ruff_cache"
            cache.mkdir()
            (cache / "CACHEDIR.TAG").mkdir()

            detection = inspect_ruff_cache(cache)

            self.assertEqual(
                _evidence_for(detection, "ruff_cache_marker")[0].observation_status,
                ObservationStatus.FAILED,
            )
            self.assertTrue(detection.contract_assessment().has_uncertainty)
            self.assertIsNone(interpret_ruff_cache(detection).provenance)

    def test_conflicting_marker_evidence_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            cache = Path(temporary_directory) / ".ruff_cache"
            _write_valid_cache(cache)
            detection = inspect_ruff_cache(cache)
            conflicting = replace(
                detection,
                observations=detection.observations
                + (
                    Evidence(
                        key="ruff_cache_marker",
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
                interpret_ruff_cache(conflicting).regenerability,
                RegenerabilityState.CONFLICTING,
            )

    def test_repeated_evaluation_is_deterministic(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            cache = Path(temporary_directory) / ".ruff_cache"
            _write_valid_cache(cache)

            first = inspect_ruff_cache(cache)
            second = inspect_ruff_cache(cache)

            self.assertEqual(first, second)
            self.assertEqual(
                interpret_ruff_cache(first),
                interpret_ruff_cache(second),
            )


if __name__ == "__main__":
    unittest.main()
