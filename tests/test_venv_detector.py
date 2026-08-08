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
    inspect_python_venv,
    interpret_python_venv,
)


def _evidence_for(detection, key: str):
    return [item for item in detection.observations if item.key == key]


def _write_valid_venv(path: Path) -> None:
    path.mkdir()
    (path / "pyvenv.cfg").write_text(
        "home = C:/Python313\ninclude-system-site-packages = false\nversion = 3.13.0\n",
        encoding="utf-8",
    )
    scripts = path / "Scripts"
    scripts.mkdir()
    (scripts / "python.exe").write_bytes(b"synthetic-interpreter")


class PythonVenvDetectorTests(unittest.TestCase):
    def test_valid_venv_is_conditional_and_stays_separate_from_risk(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory) / ".venv"
            _write_valid_venv(path)

            detection = inspect_python_venv(path)
            interpretation = interpret_python_venv(detection)

            self.assertEqual(detection.node.kind, NodeKind.DIRECTORY)
            self.assertIsNotNone(interpretation.provenance)
            self.assertEqual(
                interpretation.provenance.generator,
                "python-virtual-environment",
            )
            self.assertEqual(
                interpretation.regenerability,
                RegenerabilityState.CONDITIONALLY_REPRODUCIBLE,
            )
            self.assertEqual(interpretation.regeneration_cost.value, "unknown")
            self.assertEqual(interpretation.reachability, ReachabilityState.UNKNOWN)
            self.assertEqual(interpretation.protection, ProtectionClass.UNKNOWN)
            self.assertFalse(hasattr(interpretation, "risk_label"))

    def test_name_only_match_does_not_establish_venv_identity(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory) / ".venv"
            path.mkdir()
            (path / "notes.txt").write_text("unrelated", encoding="utf-8")

            detection = inspect_python_venv(path)
            interpretation = interpret_python_venv(detection)

            self.assertIsNone(interpretation.provenance)
            self.assertEqual(
                _evidence_for(detection, "pyvenv_cfg_marker")[0].observation_status,
                ObservationStatus.CONFIRMED_ABSENT,
            )

    def test_partial_structure_is_weak(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory) / "venv"
            _write_valid_venv(path)
            (path / "Scripts" / "python.exe").write_bytes(b"")

            detection = inspect_python_venv(path)
            interpretation = interpret_python_venv(detection)

            self.assertIn(
                "interpreter_layout_observation",
                detection.contract_assessment().confidence_shortfalls,
            )
            self.assertIsNone(interpretation.provenance)

    def test_corrupt_metadata_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory) / ".venv"
            path.mkdir()
            (path / "pyvenv.cfg").write_text("home =\nversion = broken\n", encoding="utf-8")
            (path / "Scripts").mkdir()
            (path / "Scripts" / "python.exe").write_bytes(b"synthetic")

            detection = inspect_python_venv(path)

            self.assertEqual(
                _evidence_for(detection, "pyvenv_cfg_marker")[0].observation_status,
                ObservationStatus.FAILED,
            )
            self.assertIsNone(interpret_python_venv(detection).provenance)

    def test_unreadable_marker_shape_fails_without_guessing(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory) / ".venv"
            path.mkdir()
            (path / "pyvenv.cfg").mkdir()

            detection = inspect_python_venv(path)

            self.assertEqual(
                _evidence_for(detection, "pyvenv_cfg_marker")[0].observation_status,
                ObservationStatus.CONFIRMED_ABSENT,
            )
            self.assertIsNone(interpret_python_venv(detection).provenance)

    def test_confirmed_reference_is_hard_gate_state(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory) / ".venv"
            _write_valid_venv(path)
            detection = inspect_python_venv(path)
            referenced = replace(
                detection,
                observations=tuple(
                    item for item in detection.observations
                    if item.key != "reference_check_observation"
                ) + (
                    Evidence(
                        key="reference_check_observation",
                        source="synthetic-test",
                        description="A synthetic active consumer was confirmed.",
                        observation_status=ObservationStatus.OBSERVED,
                        polarity=EvidencePolarity.SUPPORTS,
                        confidence=Confidence.HIGH,
                    ),
                ),
            )

            self.assertEqual(
                interpret_python_venv(referenced).reachability,
                ReachabilityState.CONFIRMED_REFERENCED,
            )

    def test_conflicting_evidence_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory) / ".venv"
            _write_valid_venv(path)
            detection = inspect_python_venv(path)
            conflicting = replace(
                detection,
                observations=detection.observations + (
                    Evidence(
                        key="pyvenv_cfg_marker",
                        source="synthetic-test",
                        description="A synthetic contradiction.",
                        observation_status=ObservationStatus.CONFIRMED_ABSENT,
                        polarity=EvidencePolarity.CONTRADICTS,
                        confidence=Confidence.HIGH,
                    ),
                ),
            )

            self.assertTrue(conflicting.contract_assessment().has_conflicts)
            self.assertEqual(
                interpret_python_venv(conflicting).regenerability,
                RegenerabilityState.CONFLICTING,
            )

    def test_repeated_evaluation_is_deterministic(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory) / ".venv"
            _write_valid_venv(path)

            first = inspect_python_venv(path)
            second = inspect_python_venv(path)

            self.assertEqual(first, second)
            self.assertEqual(interpret_python_venv(first), interpret_python_venv(second))


if __name__ == "__main__":
    unittest.main()
