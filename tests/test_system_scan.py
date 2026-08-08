import os
import stat
import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import dwi.global_storage as global_storage

from dwi import (
    ArtifactKind,
    AnalysisResult,
    GlobalStorageInterpretation,
    RootBoundary,
    RootRequest,
    RootScope,
    RootStatus,
    ScanBudget,
    ScanLimits,
    ScanTermination,
    SystemScanOptions,
    evaluate_analysis,
    inspect_global_storage,
    interpret_global_storage,
    json_system_report,
    scan_system,
    table_system_report,
)
from dwi.__main__ import main


_TAG = "Signature: 8a477f597d28d172789f06886806bc55\n"


class SystemScanTests(unittest.TestCase):
    def _root_options(self, root: Path, **overrides) -> SystemScanOptions:
        values = {
            "additional_roots": (str(root),),
            "include_global_storage": False,
            "allow_network": True,
        }
        values.update(overrides)
        return SystemScanOptions(**values)

    def _workspace(self, root: Path) -> None:
        cache = root / ".pytest_cache"
        cache.mkdir()
        (cache / "CACHEDIR.TAG").write_text(_TAG, encoding="utf-8")

    def test_system_defaults_have_bounded_limits(self) -> None:
        options = SystemScanOptions()
        self.assertIsNotNone(options.limits.max_seconds)
        self.assertIsNotNone(options.limits.max_nodes)
        self.assertIsNotNone(options.limits.max_files)

    def test_cli_preserves_safe_default_limits_when_flags_are_omitted(self) -> None:
        with patch("dwi.__main__.scan_system", return_value=object()) as scan_mock, patch(
            "dwi.__main__.table_system_report", return_value=""
        ):
            self.assertEqual(main(["scan-system", "--root", "C:\\synthetic"]), 0)
        actual = scan_mock.call_args.args[0].limits
        expected = SystemScanOptions().limits
        self.assertEqual(actual, expected)

    def test_cli_limit_flags_override_only_the_supplied_limit(self) -> None:
        with patch("dwi.__main__.scan_system", return_value=object()) as scan_mock, patch(
            "dwi.__main__.table_system_report", return_value=""
        ):
            self.assertEqual(main(["scan-system", "--root", "C:\\synthetic", "--max-nodes", "7"]), 0)
        actual = scan_mock.call_args.args[0].limits
        expected = SystemScanOptions().limits
        self.assertEqual(actual.max_nodes, 7)
        self.assertEqual(actual.max_seconds, expected.max_seconds)
        self.assertEqual(actual.max_files, expected.max_files)

    def test_explicit_root_scans_with_structured_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            self._workspace(root)
            result = scan_system(self._root_options(root))
            self.assertEqual(result.termination, ScanTermination.COMPLETED)
            self.assertEqual(len(result.workspace_findings), 1)
            self.assertEqual(result.root_observations[0].status, RootStatus.SCANNED)
            self.assertEqual(result.summary.workspace_findings, 1)

    def test_unc_is_denied_by_default(self) -> None:
        result = scan_system(SystemScanOptions(additional_roots=(r"\\server\share",), include_global_storage=False))
        self.assertEqual(result.root_observations[0].boundary, RootBoundary.UNC)
        self.assertEqual(result.root_observations[0].status, RootStatus.DENIED)
        self.assertTrue(result.denied_network_boundaries)

    def test_drive_boundary_classification_distinguishes_fixed_and_mapped(self) -> None:
        with patch("dwi.system_scan.os.name", "nt"), patch("dwi.system_scan._windows_drive_type", return_value=3):
            from dwi import classify_root
            self.assertEqual(classify_root(r"C:\\"), RootBoundary.LOCAL_FIXED_DRIVE)
        with patch("dwi.system_scan.os.name", "nt"), patch("dwi.system_scan._windows_drive_type", return_value=4):
            from dwi import classify_root
            self.assertEqual(classify_root(r"Z:\\"), RootBoundary.MAPPED_DRIVE)

    def test_network_opt_in_does_not_guess_missing_root(self) -> None:
        result = scan_system(SystemScanOptions(
            additional_roots=(r"\\server\share\missing",),
            include_global_storage=False,
            allow_network=True,
        ))
        self.assertEqual(result.root_observations[0].boundary, RootBoundary.UNC)
        self.assertIn(result.root_observations[0].status, {RootStatus.SKIPPED, RootStatus.FAILED})
        self.assertFalse(result.findings)

    def test_explicit_network_opt_in_is_required_for_network_boundary(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            with patch("dwi.system_scan.classify_root", return_value=RootBoundary.NETWORK):
                denied = scan_system(self._root_options(root, allow_network=False))
                allowed = scan_system(self._root_options(root, allow_network=True))
            self.assertEqual(denied.root_observations[0].status, RootStatus.DENIED)
            self.assertEqual(allowed.root_observations[0].status, RootStatus.SCANNED)

    def test_symlink_root_is_denied_without_following(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            base = Path(temporary_directory)
            target = base / "target"
            target.mkdir()
            link = base / "link"
            try:
                link.symlink_to(target, target_is_directory=True)
            except (OSError, NotImplementedError):
                self.skipTest("symlink creation unavailable")
            result = scan_system(self._root_options(link))
            self.assertEqual(result.root_observations[0].status, RootStatus.DENIED)
            self.assertIn("symlink", result.root_observations[0].reason)

    def test_inaccessible_root_is_recorded_and_scan_continues(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            with patch("dwi.system_scan.os.lstat", side_effect=PermissionError()):
                result = scan_system(self._root_options(root))
            self.assertEqual(result.root_observations[0].status, RootStatus.FAILED)
            self.assertFalse(result.findings)

    def test_disappearing_entry_is_recorded_without_guessing(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            with patch("dwi.scanner.os.scandir", side_effect=FileNotFoundError()):
                result = scan_system(self._root_options(root))
            self.assertEqual(result.root_observations[0].status, RootStatus.PARTIAL)
            self.assertTrue(result.observation_failures)

    def test_cancellation_returns_deterministic_partial_result(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            self._workspace(root)
            result = scan_system(self._root_options(root, cancellation=lambda: True))
            self.assertEqual(result.termination, ScanTermination.CANCELLED)
            self.assertEqual(result.root_observations[0].status, RootStatus.SKIPPED)

    def test_node_limit_returns_partial_result_without_reclaim_guess(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            self._workspace(root)
            options = self._root_options(root, limits=ScanLimits(max_nodes=1))
            first = scan_system(options)
            second = scan_system(options)
            self.assertEqual(first.termination, ScanTermination.NODE_LIMIT)
            self.assertEqual(first, second)
            self.assertEqual(first.summary.potentially_reclaimable_bytes, 0)

    def test_global_pip_cache_requires_structure(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory) / "pip-cache"
            root.mkdir()
            (root / "http-v2").mkdir()
            (root / "wheels").mkdir()
            request = RootRequest(str(root), RootScope.GLOBAL_STORAGE, "pip-cache", ArtifactKind.PIP_CACHE)
            result = scan_system(SystemScanOptions(
                include_fixed_drives=False,
                include_user_profile=False,
                global_storage_roots=(request,),
                allow_network=True,
            ))
            self.assertEqual(len(result.global_storage_findings), 1)
            finding = result.global_storage_findings[0]
            self.assertEqual(finding.artifact, ArtifactKind.PIP_CACHE)
            self.assertIsInstance(finding.interpretation, GlobalStorageInterpretation)
            self.assertEqual(finding.interpretation.regenerability.value, "conditionally_reproducible")
            self.assertEqual(finding.interpretation.regeneration_cost.value, "unknown")
            self.assertEqual(finding.risk_label.value, "review_required")

    def test_global_name_only_match_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory) / "pip-cache"
            root.mkdir()
            detection = inspect_global_storage(root, ArtifactKind.PIP_CACHE, approved_root=True)
            interpretation = interpret_global_storage(detection)
            finding = evaluate_analysis(
                AnalysisResult(ArtifactKind.PIP_CACHE, detection, interpretation)
            )
            self.assertIsNone(interpretation.provenance)
            self.assertEqual(finding.risk_label.value, "review_required")
            self.assertEqual(finding.action_eligibility.value, "requires_review")

    def test_each_global_cache_layout_requires_tool_specific_markers(self) -> None:
        layouts = {
            ArtifactKind.PIP_CACHE: ("http-v2", "wheels"),
            ArtifactKind.UV_CACHE: ("archive-v0", "wheels-v1"),
            ArtifactKind.NPM_CACHE: ("content-v2", "index-v5"),
        }
        with tempfile.TemporaryDirectory() as temporary_directory:
            base = Path(temporary_directory)
            for artifact, names in layouts.items():
                with self.subTest(artifact=artifact):
                    root = base / artifact.value
                    root.mkdir()
                    for name in names:
                        (root / name).mkdir()
                    detection = inspect_global_storage(root, artifact, approved_root=True)
                    self.assertIsNotNone(interpret_global_storage(detection).provenance)

            pnpm = base / "pnpm"
            (pnpm / "v3" / "files").mkdir(parents=True)
            (pnpm / "v3" / "index").mkdir()
            self.assertIsNotNone(interpret_global_storage(
                inspect_global_storage(pnpm, ArtifactKind.PNPM_CACHE, approved_root=True)
            ).provenance)

            yarn = base / "yarn"
            metadata = yarn / "package-entry" / ".yarn-metadata.json"
            metadata.parent.mkdir(parents=True)
            metadata.write_text("{}", encoding="utf-8")
            self.assertIsNotNone(interpret_global_storage(
                inspect_global_storage(yarn, ArtifactKind.YARN_CACHE, approved_root=True)
            ).provenance)

    def test_global_structure_cancellation_is_bounded_and_explicit(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            for index in range(40):
                (root / f"entry-{index:03d}").mkdir()
            calls = [0]

            def cancel() -> bool:
                calls[0] += 1
                return calls[0] >= 5

            budget = ScanBudget(cancellation=cancel)
            detection = inspect_global_storage(root, ArtifactKind.PIP_CACHE, approved_root=True, budget=budget)
            self.assertEqual(budget.termination, ScanTermination.CANCELLED)
            self.assertTrue(any("scan-limit:cancelled" in item.description for item in detection.evidence.observations))
            self.assertLess(budget.nodes_observed, 40)

    def test_global_structure_node_and_file_limits_terminate_before_unbounded_work(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            for index in range(40):
                (root / f"entry-{index:03d}").mkdir()
            budget = ScanBudget(limits=ScanLimits(max_nodes=3))
            inspect_global_storage(root, ArtifactKind.PIP_CACHE, approved_root=True, budget=budget)
            self.assertEqual(budget.termination, ScanTermination.NODE_LIMIT)
            self.assertLessEqual(budget.nodes_observed, 3)

            for child in root.iterdir():
                child.rmdir()
            for index in range(40):
                (root / f"file-{index:03d}").write_text("x", encoding="utf-8")
            budget = ScanBudget(limits=ScanLimits(max_files=3))
            inspect_global_storage(root, ArtifactKind.PIP_CACHE, approved_root=True, budget=budget)
            self.assertEqual(budget.termination, ScanTermination.FILE_LIMIT)
            self.assertLessEqual(budget.files_observed, 3)

    def test_global_structure_time_limit_is_deterministic(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            (root / "http-v2").mkdir()
            budget = ScanBudget(limits=ScanLimits(max_seconds=1), started_at=0)
            with patch("dwi.scan_control.time.monotonic", return_value=2):
                first = inspect_global_storage(root, ArtifactKind.PIP_CACHE, approved_root=True, budget=budget)
            self.assertEqual(budget.termination, ScanTermination.TIME_LIMIT)
            second_budget = ScanBudget(limits=ScanLimits(max_seconds=1), started_at=0)
            with patch("dwi.scan_control.time.monotonic", return_value=2):
                second = inspect_global_storage(root, ArtifactKind.PIP_CACHE, approved_root=True, budget=second_budget)
            self.assertEqual(first.evidence, second.evidence)

    def test_global_root_replacement_is_rejected_before_enumeration(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory) / "pip-cache"
            root.mkdir()
            external = Path(temporary_directory) / "external"
            external.mkdir()
            (external / "http-v2").mkdir()
            real_lstat = os.lstat
            calls = [0]
            scanned: list[str] = []
            real_scandir = os.scandir

            def changing_lstat(path):
                result = real_lstat(path)
                if Path(path) == root:
                    calls[0] += 1
                    if calls[0] >= 2:
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

            with patch("dwi.global_storage.os.lstat", side_effect=changing_lstat), patch(
                "dwi.global_storage.os.scandir", side_effect=recording_scandir
            ):
                detection = inspect_global_storage(root, ArtifactKind.PIP_CACHE, approved_root=True)
            self.assertIn("symlink", " ".join(item.description for item in detection.evidence.observations))
            self.assertNotIn(str(external), scanned)
            self.assertIsNone(interpret_global_storage(detection).provenance)

    def test_global_root_reparse_replacement_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory) / "pip-cache"
            root.mkdir()
            real_lstat = os.lstat
            calls = [0]

            def changing_lstat(path):
                result = real_lstat(path)
                if Path(path) == root:
                    calls[0] += 1
                    if calls[0] >= 2:
                        return SimpleNamespace(
                            st_mode=result.st_mode,
                            st_dev=result.st_dev,
                            st_ino=result.st_ino,
                            st_file_attributes=0x400,
                        )
                return result

            with patch("dwi.global_storage.os.lstat", side_effect=changing_lstat):
                detection = inspect_global_storage(root, ArtifactKind.PIP_CACHE, approved_root=True)
            self.assertIn("reparse", " ".join(item.description for item in detection.evidence.observations))
            self.assertIsNone(interpret_global_storage(detection).provenance)

    def test_global_containment_failure_fails_closed_and_is_deterministic(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory) / "pip-cache"
            root.mkdir()
            (root / "http-v2").mkdir()
            real_within_root = global_storage._within_root

            def outside_only(container, path):
                return False if Path(path) != Path(container) else real_within_root(container, path)

            with patch("dwi.global_storage._within_root", side_effect=outside_only):
                first = inspect_global_storage(root, ArtifactKind.PIP_CACHE, approved_root=True)
            with patch("dwi.global_storage._within_root", side_effect=outside_only):
                second = inspect_global_storage(root, ArtifactKind.PIP_CACHE, approved_root=True)
            self.assertEqual(first, second)
            self.assertTrue(any("outside-approved-root" in item.description for item in first.evidence.observations))
            self.assertIsNone(interpret_global_storage(first).provenance)

    def test_global_detector_failures_propagate_once_to_system_diagnostics(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory) / "pip-cache"
            root.mkdir()
            request = RootRequest(str(root), RootScope.GLOBAL_STORAGE, "pip-cache", ArtifactKind.PIP_CACHE)
            with patch("dwi.global_storage._direct_entries", return_value=({}, False, "synthetic-structure-failure")):
                first = scan_system(SystemScanOptions(
                    include_fixed_drives=False,
                    include_user_profile=False,
                    global_storage_roots=(request,),
                    allow_network=True,
                ))
            finding = first.global_storage_findings[0]
            failed_evidence = [
                item for item in finding.evidence.observations
                if item.key == "global_storage_structure_observation" and item.observation_status.value == "failed"
            ]
            self.assertTrue(failed_evidence)
            matching = [item for item in first.observation_failures if "global_storage_structure_observation" in item]
            self.assertEqual(len(matching), 1)
            self.assertEqual(first.root_observations[0].status, RootStatus.PARTIAL)
            self.assertEqual(first.summary.observation_failure_count, len(first.observation_failures))
            with patch("dwi.global_storage._direct_entries", return_value=({}, False, "synthetic-structure-failure")):
                second = scan_system(SystemScanOptions(
                    include_fixed_drives=False,
                    include_user_profile=False,
                    global_storage_roots=(request,),
                    allow_network=True,
                ))
            self.assertEqual(first, second)
            parsed = json.loads(json_system_report(first))
            self.assertEqual(parsed["summary"]["observation_failure_count"], first.summary.observation_failure_count)

    def test_json_and_table_separate_global_storage_and_partial_state(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            self._workspace(root)
            result = scan_system(self._root_options(root, limits=ScanLimits(max_nodes=1)))
            parsed = json.loads(json_system_report(result))
            self.assertIn("workspace_findings", parsed)
            self.assertIn("global_storage_findings", parsed)
            self.assertIn("roots_denied_or_skipped", parsed)
            self.assertIn("partial_known_bytes", parsed["summary"])
            table = table_system_report(result)
            self.assertIn("REGENERABILITY", table)
            self.assertIn("Protected Git paths:", table)
            self.assertIn("Ambiguous/reparse boundaries:", table)
            self.assertIn("Denied network boundaries:", table)
            self.assertIn("Partial:", table)

    def test_cli_scan_system_supports_synthetic_root_and_json(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            self._workspace(root)
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                self.assertEqual(main(["scan-system", "--root", str(root), "--allow-network"]), 0)
            self.assertIn("Workspace artifacts", output.getvalue())
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                self.assertEqual(main(["scan-system", "--root", str(root), "--allow-network", "--json"]), 0)
            self.assertEqual(json.loads(output.getvalue())["scan_metadata"]["termination"], "completed")


if __name__ == "__main__":
    unittest.main()
