import tempfile
import unittest
from pathlib import Path

from dwi import SizeObservation, analyze_candidate, collect_size, evaluate_analysis
from dwi.scanner import WorkspaceScan


class SizeTests(unittest.TestCase):
    def test_size_is_deterministic_and_does_not_follow_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory) / "workspace"
            root.mkdir()
            (root / "a.txt").write_bytes(b"123")
            nested = root / "nested"
            nested.mkdir()
            (nested / "b.txt").write_bytes(b"12345")
            outside = Path(temporary_directory) / "outside.txt"
            outside.write_bytes(b"outside")
            link = root / "link.txt"
            try:
                link.symlink_to(outside)
            except (OSError, NotImplementedError):
                link = None
            first = collect_size(root)
            second = collect_size(root)
            self.assertEqual(first, second)
            self.assertEqual(first.known_bytes, 8)
            if link is not None:
                self.assertFalse(first.complete)
                self.assertIn(str(link), first.links_skipped)

    def test_missing_path_is_incomplete(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            result = collect_size(Path(temporary_directory) / "missing")
            self.assertFalse(result.complete)
            self.assertEqual(result.known_bytes, 0)
            self.assertTrue(result.observation_failures)

    def test_incomplete_size_retains_known_bytes(self) -> None:
        result = SizeObservation(12, False, ("synthetic-failure",))
        self.assertEqual(result.known_bytes, 12)
        self.assertFalse(result.complete)

    def test_incomplete_size_is_not_potentially_reclaimable(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory) / ".pytest_cache"
            path.mkdir()
            (path / "CACHEDIR.TAG").write_text("Signature: 8a477f597d28d172789f06886806bc55\n", encoding="utf-8")
            analysis = analyze_candidate(path)
            assert analysis is not None
            finding = evaluate_analysis(analysis, size=SizeObservation(12, False, ("synthetic-failure",)))
            scan = WorkspaceScan(root=temporary_directory, findings=(finding,))
            self.assertEqual(scan.summary.known_analyzed_bytes, 12)
            self.assertEqual(scan.summary.potentially_reclaimable_bytes, 0)


if __name__ == "__main__":
    unittest.main()
