import os
import stat
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

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

    def test_directory_replacement_is_incomplete_and_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            (root / "file.txt").write_text("x", encoding="utf-8")
            real_lstat = os.lstat
            calls = [0]

            def changing_lstat(path):
                calls[0] += 1
                result = real_lstat(path)
                if Path(path) == root and calls[0] >= 2:
                    return SimpleNamespace(
                        st_mode=stat.S_IFLNK | 0o777,
                        st_dev=result.st_dev,
                        st_ino=result.st_ino,
                        st_file_attributes=0,
                    )
                return result

            with patch("dwi.size.os.lstat", side_effect=changing_lstat):
                result = collect_size(root)
            self.assertFalse(result.complete)
            self.assertIn(f"{root}: traversal-race", result.observation_failures)


if __name__ == "__main__":
    unittest.main()
