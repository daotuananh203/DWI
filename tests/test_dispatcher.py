import tempfile
import unittest
from pathlib import Path

from dwi import ArtifactKind, AnalysisResult, analyze_candidate, dispatch_analysis


class DispatcherTests(unittest.TestCase):
    def test_dispatcher_selects_one_explicit_candidate_without_discovery(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            candidate = Path(temporary_directory) / ".venv"
            candidate.mkdir()

            result = analyze_candidate(candidate)

            self.assertIsInstance(result, AnalysisResult)
            self.assertEqual(result.artifact, ArtifactKind.PYTHON_VENV)
            self.assertEqual(result.detection.node.path, str(candidate))

    def test_dispatcher_covers_all_bounded_artifact_names(self) -> None:
        names = {
            "__pycache__": ArtifactKind.PYCACHE,
            ".pytest_cache": ArtifactKind.PYTEST_CACHE,
            ".mypy_cache": ArtifactKind.MYPY_CACHE,
            ".ruff_cache": ArtifactKind.RUFF_CACHE,
            ".venv": ArtifactKind.PYTHON_VENV,
            "venv": ArtifactKind.PYTHON_VENV,
            "node_modules": ArtifactKind.NODE_MODULES,
            "dist": ArtifactKind.DIST,
            "build": ArtifactKind.BUILD,
            ".next": ArtifactKind.NEXT_BUILD,
        }
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            for name, artifact in names.items():
                with self.subTest(name=name):
                    result = dispatch_analysis(root / name)
                    self.assertIsNotNone(result)
                    self.assertEqual(result.artifact, artifact)

    def test_unknown_name_is_not_discovered_or_reinterpreted(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            (root / "dist").mkdir()
            (root / "unrelated").mkdir()

            self.assertIsNone(analyze_candidate(root / "unrelated"))

    def test_dispatcher_is_deterministic_for_same_candidate(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            candidate = Path(temporary_directory) / "build"
            candidate.mkdir()

            first = analyze_candidate(candidate)
            second = analyze_candidate(candidate)

            self.assertEqual(first, second)


if __name__ == "__main__":
    unittest.main()
