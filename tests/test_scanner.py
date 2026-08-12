import os
import stat
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

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

    def test_explicitly_marked_disposable_root_produces_executable_pytest_cache_finding(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            (root / ".dwi-disposable-root").write_text("DWI-DISPOSABLE-ROOT-v0.3\n", encoding="utf-8")
            cache = root / ".pytest_cache"
            cache.mkdir()
            (cache / "CACHEDIR.TAG").write_text(_TAG, encoding="utf-8")
            (cache / "README.md").write_text("This directory is used by pytest to store cache data.\n", encoding="utf-8")
            (cache / "v").mkdir()

            scan = scan_workspace(root)
            self.assertEqual(len(scan.findings), 1)
            finding = scan.findings[0]
            self.assertEqual(finding.risk_label, RiskLabel.REGENERATABLE)
            self.assertEqual(finding.action_eligibility.value, "eligible_for_explicit_action")
            self.assertEqual(finding.interpretation.reachability.value, "confirmed_unreferenced")
            self.assertEqual(finding.interpretation.activity.value, "inactive")
            self.assertEqual(finding.interpretation.protection.value, "ordinary")
            self.assertFalse(finding.evidence.has_uncertainty)
            self.assertFalse(finding.evidence.has_conflicts)

    def test_ambiguous_marked_root_variant_remains_review_required(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            (root / ".dwi-disposable-root").write_text("DWI-DISPOSABLE-ROOT-v0.3\n", encoding="utf-8")
            cache = root / ".pytest_cache"
            cache.mkdir()
            (cache / "CACHEDIR.TAG").write_text("not the standard signature\n", encoding="utf-8")
            (cache / "v").mkdir()

            finding = scan_workspace(root).findings[0]
            self.assertEqual(finding.risk_label, RiskLabel.REVIEW_REQUIRED)
            self.assertEqual(finding.action_eligibility.value, "requires_review")

    def test_repeated_scan_is_deterministic(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            self._workspace(root)
            self.assertEqual(scan_workspace(root), scan_workspace(root))

    def test_directory_replacement_is_recorded_as_traversal_race(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            (root / "nested").mkdir()
            real_lstat = os.lstat
            calls = [0]

            def changing_lstat(path):
                calls[0] += 1
                result = real_lstat(path)
                if Path(path) == root and calls[0] >= 3:
                    return SimpleNamespace(
                        st_mode=result.st_mode,
                        st_dev=result.st_dev,
                        st_ino=result.st_ino + 1,
                        st_file_attributes=0,
                    )
                return result

            with patch("dwi.scanner.os.lstat", side_effect=changing_lstat):
                scan = scan_workspace(root)
            self.assertIn(str(root), scan.ambiguous_paths)
            self.assertIn(f"{root}: traversal-race", scan.observation_failures)

    def test_child_type_replacement_is_recorded_without_following(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            child = root / ".pytest_cache"
            child.mkdir()
            real_lstat = os.lstat
            child_calls = [0]

            def changing_lstat(path):
                result = real_lstat(path)
                if Path(path) == child:
                    child_calls[0] += 1
                    if child_calls[0] >= 2:
                        return SimpleNamespace(
                            st_mode=stat.S_IFLNK | 0o777,
                            st_dev=result.st_dev,
                            st_ino=result.st_ino,
                            st_file_attributes=0,
                        )
                return result

            with patch("dwi.scanner.os.lstat", side_effect=changing_lstat):
                scan = scan_workspace(root)
            self.assertFalse(scan.findings)
            self.assertIn(str(child), scan.ambiguous_paths)
            self.assertIn(f"{child}: traversal-race", scan.observation_failures)

    def test_current_stack_path_symlink_is_rejected_before_scandir(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            base = Path(temporary_directory)
            root = base / "root"
            root.mkdir()
            current = root / "nested"
            current.mkdir()
            outside = base / "outside"
            outside.mkdir()
            (outside / ".pytest_cache").mkdir()
            real_lstat = os.lstat
            real_scandir = os.scandir
            current_calls = [0]
            scanned: list[str] = []

            def changing_lstat(path):
                result = real_lstat(path)
                if Path(path) == current:
                    current_calls[0] += 1
                    if current_calls[0] >= 4:
                        return SimpleNamespace(
                            st_mode=stat.S_IFLNK | 0o777,
                            st_dev=result.st_dev,
                            st_ino=result.st_ino,
                            st_file_attributes=0,
                        )
                return result

            def recording_scandir(path):
                scanned.append(str(path))
                return real_scandir(path)

            with patch("dwi.scanner.os.lstat", side_effect=changing_lstat), patch(
                "dwi.scanner.os.scandir", side_effect=recording_scandir
            ):
                scan = scan_workspace(root)
            self.assertIn(f"{current}: current-node-symlink", scan.observation_failures)
            self.assertNotIn(str(current), scanned)
            self.assertFalse(scan.findings)

    def test_current_stack_path_reparse_is_rejected_before_scandir(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            current = root / "nested"
            current.mkdir()
            real_lstat = os.lstat
            current_calls = [0]

            def changing_lstat(path):
                result = real_lstat(path)
                if Path(path) == current:
                    current_calls[0] += 1
                    if current_calls[0] >= 4:
                        return SimpleNamespace(
                            st_mode=result.st_mode,
                            st_dev=result.st_dev,
                            st_ino=result.st_ino,
                            st_file_attributes=0x400,
                        )
                return result

            with patch("dwi.scanner.os.lstat", side_effect=changing_lstat):
                scan = scan_workspace(root)
            self.assertIn(f"{current}: current-node-reparse", scan.observation_failures)
            self.assertIn(str(current), scan.ambiguous_paths)

    def test_current_stack_path_disappearance_is_recorded_before_scandir(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            current = root / "nested"
            current.mkdir()
            real_lstat = os.lstat
            current_calls = [0]

            def changing_lstat(path):
                if Path(path) == current:
                    current_calls[0] += 1
                    if current_calls[0] >= 4:
                        raise FileNotFoundError()
                return real_lstat(path)

            with patch("dwi.scanner.os.lstat", side_effect=changing_lstat):
                scan = scan_workspace(root)
            self.assertIn(str(current), scan.ambiguous_paths)
            self.assertIn(f"{current}: FileNotFoundError", scan.observation_failures)

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
