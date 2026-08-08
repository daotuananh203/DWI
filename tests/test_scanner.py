import tempfile
import unittest
from pathlib import Path

from dwi import RiskLabel, WorkspaceScanError, scan_to_dict, scan_workspace


_TAG = "Signature: 8a477f597d28d172789f06886806bc55\n"


class ScannerTests(unittest.TestCase):
    def _workspace(self, root: Path) -> None:
        cache = root / "project" / ".pytest_cache"
        cache.mkdir(parents=True)
        (cache / "CACHEDIR.TAG").write_text(_TAG, encoding="utf-8")
        (root / "project" / "dist").mkdir()
        (root / "project" / "dist" / "index.js").write_text("user output", encoding="utf-8")
        (root / "project" / "node_modules" / "nested-dist").mkdir(parents=True)
        (root / "project" / "node_modules" / "nested-dist" / "index.js").write_text("not separately discovered", encoding="utf-8")
        (root / "source.py").write_text("print('source')", encoding="utf-8")
        (root / ".git").mkdir()
        (root / ".git" / "HEAD").write_text("ref: refs/heads/main", encoding="utf-8")
        (root / ".git" / "config").write_text("[core]\n", encoding="utf-8")
        (root / ".git" / "objects").mkdir()
        (root / ".git" / "refs").mkdir()

    def test_discovers_supported_candidates_and_skips_git_and_unknown_names(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            self._workspace(root)
            scan = scan_workspace(root)
            self.assertEqual(len(scan.findings), 3)
            self.assertEqual(
                [Path(item.path).name for item in scan.findings],
                [".pytest_cache", "dist", "node_modules"],
            )
            self.assertIn(str(root / ".git"), scan.protected_git_paths)
            self.assertEqual(len(scan.git_observations), 1)
            self.assertEqual(scan.git_observations[0].node.kind.value, "git_directory")
            serialized = scan_to_dict(scan)
            self.assertEqual(len(serialized["git_observations"]), 1)
            self.assertEqual(serialized["git_observations"][0]["object_form"], "directory")
            self.assertEqual(scan.summary.candidates_discovered, 3)
            self.assertEqual(scan.summary.findings_by_risk[-1][0], RiskLabel.NEVER_DELETE.value)

    def test_candidate_directories_are_not_recursively_discovered(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            self._workspace(root)
            scan = scan_workspace(root)
            self.assertEqual(sum(Path(item.path).name == "dist" for item in scan.findings), 1)
            self.assertNotIn("nested-dist", [Path(item.path).name for item in scan.findings])

    def test_symlink_boundary_is_not_followed_when_supported(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory) / "root"
            root.mkdir()
            outside = Path(temporary_directory) / "outside"
            outside.mkdir()
            (outside / ".pytest_cache").mkdir()
            link = root / "linked"
            try:
                link.symlink_to(outside, target_is_directory=True)
            except (OSError, NotImplementedError):
                self.skipTest("symlink creation unavailable")
            scan = scan_workspace(root)
            self.assertFalse(scan.findings)
            self.assertIn(str(link), scan.ambiguous_paths)

    def test_invalid_root_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            with self.assertRaises(WorkspaceScanError):
                scan_workspace(Path(temporary_directory) / "missing")

    def test_repeated_scan_is_deterministic(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            self._workspace(root)
            self.assertEqual(scan_workspace(root), scan_workspace(root))

    def test_git_file_is_recorded_as_context_and_not_dispatched(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            (root / ".git").write_text("gitdir: outside-worktree\n", encoding="utf-8")
            scan = scan_workspace(root)
            self.assertFalse(scan.findings)
            self.assertEqual(len(scan.git_observations), 1)
            self.assertEqual(scan.git_observations[0].node.kind.value, "git_file")
            self.assertEqual(scan.git_observations[0].reference_target, "outside-worktree")
            self.assertFalse(scan.git_observations[0].target_followed)

    def test_git_symlink_is_structured_protection_context(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            target = root / "target"
            target.mkdir()
            git_path = root / ".git"
            try:
                git_path.symlink_to(target, target_is_directory=True)
            except (OSError, NotImplementedError):
                self.skipTest("symlink creation unavailable")
            scan = scan_workspace(root)
            self.assertFalse(scan.findings)
            self.assertEqual(len(scan.git_observations), 1)
            self.assertEqual(scan.git_observations[0].node.kind.value, "symlink")
            self.assertEqual(scan.protected_git_paths, (str(git_path),))


if __name__ == "__main__":
    unittest.main()
