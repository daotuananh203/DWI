import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from dwi import (
    CleanupCandidate,
    EvidenceBundle,
    NodeKind,
    ProtectionClass,
    observe_git_path,
)


def _valid_git_directory(path: Path) -> None:
    path.mkdir()
    (path / "HEAD").write_text("ref: refs/heads/main\n", encoding="utf-8")
    (path / "config").write_text("[core]\n", encoding="utf-8")
    (path / "objects").mkdir()
    (path / "refs").mkdir()


class GitContextTests(unittest.TestCase):
    def test_valid_git_directory_is_structured_protected_context(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory) / ".git"
            _valid_git_directory(path)

            observation = observe_git_path(path)

            self.assertEqual(observation.node.kind, NodeKind.GIT_DIRECTORY)
            self.assertEqual(observation.node.protection, ProtectionClass.REPOSITORY_PROTECTED)
            self.assertTrue(observation.valid_structure)
            self.assertTrue(observation.is_protection_context)
            self.assertFalse(observation.target_followed)

    def test_valid_git_file_records_reference_without_following_target(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            path = root / ".git"
            target = root / "external-gitdir"
            target.mkdir()
            (target / "SHOULD_NOT_BE_READ").write_text("sentinel", encoding="utf-8")
            path.write_text("gitdir: external-gitdir\n", encoding="utf-8")

            observation = observe_git_path(path)

            self.assertEqual(observation.node.kind, NodeKind.GIT_FILE)
            self.assertEqual(observation.reference_target, "external-gitdir")
            self.assertFalse(observation.target_followed)
            self.assertTrue(observation.valid_structure)
            self.assertFalse(any(item.value == "sentinel" for item in observation.observations))

    def test_malformed_git_file_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory) / ".git"
            path.write_text("not a gitdir reference\n", encoding="utf-8")

            observation = observe_git_path(path)

            self.assertEqual(observation.node.kind, NodeKind.GIT_FILE)
            self.assertFalse(observation.valid_structure)
            self.assertEqual(observation.object_form.value, "ambiguous")
            self.assertEqual(observation.node.protection, ProtectionClass.REPOSITORY_PROTECTED)

    def test_missing_and_inaccessible_git_paths_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            missing = observe_git_path(Path(temporary_directory) / ".git")
            self.assertEqual(missing.node.kind, NodeKind.UNKNOWN)
            self.assertEqual(missing.object_form.value, "missing")
            self.assertEqual(missing.node.protection, ProtectionClass.REPOSITORY_PROTECTED)

            path = Path(temporary_directory) / "inaccessible" / ".git"
            with patch("dwi.git_context.os.lstat", side_effect=PermissionError):
                inaccessible = observe_git_path(path)
            self.assertEqual(inaccessible.node.kind, NodeKind.INACCESSIBLE)
            self.assertEqual(inaccessible.object_form.value, "inaccessible")
            self.assertEqual(inaccessible.node.protection, ProtectionClass.REPOSITORY_PROTECTED)

    def test_symlink_and_reparse_paths_are_not_followed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            target = root / "target"
            _valid_git_directory(target)
            link = root / ".git"
            try:
                link.symlink_to(target, target_is_directory=True)
            except (OSError, NotImplementedError):
                self.skipTest("symlink creation unavailable")
            symlink_observation = observe_git_path(link)
            self.assertEqual(symlink_observation.node.kind, NodeKind.SYMLINK)
            self.assertFalse(symlink_observation.target_followed)
            self.assertFalse(symlink_observation.valid_structure)

            regular = root / "reparse-target"
            _valid_git_directory(regular)
            reparse_path = root / "reparse" / ".git"
            reparse_path.parent.mkdir()
            _valid_git_directory(reparse_path)
            with patch("dwi.git_context._reparse", return_value=True):
                reparse_observation = observe_git_path(reparse_path)
            self.assertEqual(reparse_observation.node.kind, NodeKind.REPARSE_POINT)
            self.assertFalse(reparse_observation.target_followed)
            self.assertFalse(reparse_observation.valid_structure)

    def test_git_context_can_never_become_cleanup_candidate(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory) / ".git"
            _valid_git_directory(path)
            observation = observe_git_path(path)
            with self.assertRaises(ValueError):
                CleanupCandidate(
                    node=observation.node,
                    selection_evidence=EvidenceBundle(observations=observation.observations),
                )

    def test_repeated_observation_is_deterministic(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory) / ".git"
            _valid_git_directory(path)
            self.assertEqual(observe_git_path(path), observe_git_path(path))

    def test_non_git_path_is_rejected_by_bounded_adapter(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            with self.assertRaises(ValueError):
                observe_git_path(Path(temporary_directory) / "not-git")


if __name__ == "__main__":
    unittest.main()
