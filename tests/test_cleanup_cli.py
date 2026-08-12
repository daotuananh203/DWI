import contextlib
import io
import os
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from dwi import (
    ActionEligibility,
    ActivityState,
    ArtifactKind,
    CandidateEligibility,
    CandidateSelection,
    CleanupCandidate,
    Confidence,
    Evidence,
    EvidenceBundle,
    EvidencePolarity,
    EvidenceRequirement,
    NodeKind,
    ObservationStatus,
    ObservedNode,
    ProtectionClass,
    Provenance,
    ReachabilityState,
    RegenerabilityState,
    RegenerationCost,
    RootBoundary,
    RootObservation,
    RootScope,
    RootStatus,
    RuleTrace,
    ScanTermination,
    SizeObservation,
    WorkspaceScan,
    evaluate_safety,
)
from dwi.__main__ import main
from dwi.application import (
    CleanupApplicationResult,
    CleanupItemOutcome,
    CleanupItemResult,
    CleanupSessionState,
    _engine_revalidator,
    _trusted_snapshot_set,
    create_cleanup_session,
    create_human_confirmation,
)
from dwi.cleanup import _digest, scan_context_from_workspace_scan
from dwi.cleanup_cli import CONFIRMATION_PHRASE, _restore_human, run_cleanup
from dwi.cleanup_engine import create_workspace_cleanup_plan, workspace_mutation_runtime
from dwi.policy import SafetyContext


class CleanupCliTests(unittest.TestCase):
    def setUp(self) -> None:
        if os.name != "nt":
            self.skipTest("cleanup mutation integration is Windows-only")
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.candidate_path = self.root / ".pytest_cache"
        self.candidate_path.mkdir()
        self.scan = WorkspaceScan(
            root=str(self.root),
            findings=(self._finding(),),
            termination=ScanTermination.COMPLETED,
            nodes_observed=2,
            files_observed=0,
        )

    def _finding(self, protection: ProtectionClass = ProtectionClass.ORDINARY):
        evidence = Evidence(
            "provenance",
            "synthetic-cli-fixture",
            "Synthetic high-confidence provenance evidence.",
            ObservationStatus.OBSERVED,
            EvidencePolarity.SUPPORTS,
            Confidence.HIGH,
            "pytest",
        )
        bundle = EvidenceBundle((evidence,), (EvidenceRequirement("provenance", Confidence.HIGH),))
        candidate = CleanupCandidate(
            ObservedNode(str(self.candidate_path), NodeKind.DIRECTORY, protection),
            bundle,
        )
        selection = CandidateSelection(CandidateEligibility.SELECTED, bundle, candidate)
        from dwi import PytestCacheInterpretation
        interpretation = PytestCacheInterpretation(
            Provenance("python", "pytest", Confidence.HIGH, ("provenance",)),
            RegenerabilityState.REPRODUCIBLE,
            RegenerationCost.LOW,
            ReachabilityState.CONFIRMED_UNREFERENCED,
            ActivityState.INACTIVE,
            protection,
        )
        decision = evaluate_safety(SafetyContext(
            candidate=candidate,
            evidence=bundle,
            provenance=interpretation.provenance,
            regenerability=interpretation.regenerability,
            regeneration_cost=interpretation.regeneration_cost,
            reachability=interpretation.reachability,
            activity=interpretation.activity,
            protection=interpretation.protection,
        ))
        from dwi import Finding
        return Finding(
            ArtifactKind.PYTEST_CACHE,
            str(self.candidate_path),
            bundle,
            interpretation,
            selection,
            decision,
            SizeObservation(10, True),
        )

    def _engine_revalidator(self, scan: WorkspaceScan | None = None):
        current_scan = scan or self.scan
        context = scan_context_from_workspace_scan(current_scan)

        def callback(plan):
            return _trusted_snapshot_set(
                plan,
                {item.plan_item_id: item.snapshot for item in plan.items},
                context,
                engine_version=plan.engine_version,
                created_at="2026-01-01T00:00:00+00:00",
            )

        return _engine_revalidator(callback)

    def _run(self, *, phrase=CONFIRMATION_PHRASE, responses=()):
        output = io.StringIO()
        response_iter = iter(responses)
        with patch("dwi.cleanup_cli.scan_workspace", return_value=self.scan), \
                patch("dwi.cleanup_cli.workspace_engine_revalidator", return_value=self._engine_revalidator()), \
                contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
            code = run_cleanup(
                str(self.root),
                confirmation_phrase=phrase,
                input_fn=lambda _: next(response_iter, ""),
            )
        return code, output.getvalue()

    def _mutation_state_names(self) -> tuple[str, ...]:
        return tuple(sorted(
            path.name
            for path in self.root.iterdir()
            if path.name == ".dwi-quarantine"
            or path.name == ".dwi-journal.jsonl"
            or path.name.startswith(".dwi-claim-")
        ))

    def _assert_no_new_mutation_state(self) -> None:
        names = self._mutation_state_names()
        self.assertNotIn(".dwi-quarantine", names)
        self.assertNotIn(".dwi-journal.jsonl", names)
        self.assertFalse(any(name.startswith(".dwi-claim-") for name in names))

    def test_happy_path_review_confirmation_quarantine_and_undo(self) -> None:
        plan = create_workspace_cleanup_plan(self.scan)
        recovery_id = f"recovery-{_digest((plan.plan_id, plan.items[0].plan_item_id))[:32]}"
        code, output = self._run(responses=(recovery_id,))
        self.assertEqual(code, 0)
        self.assertIn("Cleanup review", output)
        self.assertIn("Cleanup result: executed", output)
        self.assertIn("Restored:", output)
        for field in ("provenance:", "regenerability:", "reachability:", "activity:", "protection:", "evidence:", "safety decision:", "rule trace:"):
            self.assertIn(field, output)
        self.assertTrue(self.candidate_path.exists())
        self.assertTrue((self.root / ".dwi-quarantine").is_dir())
        self.assertTrue((self.root / ".dwi-journal.jsonl").is_file())

    def test_cancellation_and_wrong_phrase_never_execute(self) -> None:
        code, output = self._run(phrase="yes")
        self.assertEqual(code, 1)
        self.assertIn("cancelled", output)
        self.assertTrue(self.candidate_path.exists())
        self._assert_no_new_mutation_state()

        code, output = self._run(phrase=None, responses=("",))
        self.assertEqual(code, 1)
        self.assertIn("cancelled", output)
        self.assertTrue(self.candidate_path.exists())
        self._assert_no_new_mutation_state()

    def test_wrong_session_confirmation_is_blocked_before_mutation(self) -> None:
        plan = create_workspace_cleanup_plan(self.scan)
        session = create_cleanup_session(plan)
        valid = create_human_confirmation(
            session,
            session.review,
            confirmation_phrase=CONFIRMATION_PHRASE,
            confirmed_at="2026-01-01T00:00:00+00:00",
        )
        forged = replace(valid, session_id="session-forged")
        output = io.StringIO()
        with patch("dwi.cleanup_cli.scan_workspace", return_value=self.scan), \
                patch("dwi.cleanup_cli.create_human_confirmation", return_value=forged), \
                patch("dwi.cleanup_cli.workspace_engine_revalidator", return_value=self._engine_revalidator()), \
                contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
            code = run_cleanup(str(self.root), confirmation_phrase=CONFIRMATION_PHRASE)
        self.assertEqual(code, 3)
        self.assertIn("blocked", output.getvalue())
        self.assertTrue(self.candidate_path.exists())
        self._assert_no_new_mutation_state()

    def test_fresh_revalidation_block_is_reported(self) -> None:
        plan = create_workspace_cleanup_plan(self.scan)
        changed_snapshot = replace(plan.items[0].snapshot, size=SizeObservation(11, True))
        context = scan_context_from_workspace_scan(self.scan)
        blocked_revalidator = _engine_revalidator(
            lambda current_plan: _trusted_snapshot_set(
                current_plan,
                {current_plan.items[0].plan_item_id: changed_snapshot},
                context,
                engine_version=current_plan.engine_version,
                created_at="2026-01-01T00:00:00+00:00",
            )
        )
        output = io.StringIO()
        with patch("dwi.cleanup_cli.scan_workspace", return_value=self.scan), \
                patch("dwi.cleanup_cli.workspace_engine_revalidator", return_value=blocked_revalidator), \
                contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
            code = run_cleanup(str(self.root), confirmation_phrase=CONFIRMATION_PHRASE)
        self.assertEqual(code, 3)
        self.assertIn("Cleanup result: blocked", output.getvalue())
        self.assertTrue(self.candidate_path.exists())
        self._assert_no_new_mutation_state()

    def test_fresh_revalidation_exception_creates_no_mutation_state(self) -> None:
        def fail_revalidation(_plan):
            raise RuntimeError("synthetic revalidation failure")

        failing_revalidator = _engine_revalidator(fail_revalidation)
        output = io.StringIO()
        with patch("dwi.cleanup_cli.scan_workspace", return_value=self.scan), \
                patch("dwi.cleanup_cli.workspace_engine_revalidator", return_value=failing_revalidator), \
                contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
            code = run_cleanup(str(self.root), confirmation_phrase=CONFIRMATION_PHRASE)
        self.assertEqual(code, 3)
        self.assertIn("Cleanup result: blocked", output.getvalue())
        self.assertTrue(self.candidate_path.exists())
        self._assert_no_new_mutation_state()

    def test_existing_recovery_state_is_inspected_without_writes(self) -> None:
        quarantine_path = self.root / ".dwi-quarantine"
        quarantine_path.mkdir()
        journal_path = self.root / ".dwi-journal.jsonl"
        journal_path.write_text("", encoding="utf-8")
        before = journal_path.read_bytes()
        before_names = self._mutation_state_names()

        plan = create_workspace_cleanup_plan(self.scan)
        runtime = workspace_mutation_runtime()
        context = runtime.provider.recovery_context(plan)

        self.assertIsNotNone(context.quarantine_root)
        self.assertEqual(before_names, self._mutation_state_names())
        self.assertEqual(before, journal_path.read_bytes())
        self.assertTrue(quarantine_path.is_dir())
        self.assertFalse(any(name.startswith(".dwi-claim-") for name in self._mutation_state_names()))

    def test_protected_finding_is_excluded_before_confirmation(self) -> None:
        protected_scan = replace(self.scan, findings=(self._finding(ProtectionClass.PROTECTED),))
        output = io.StringIO()
        with patch("dwi.cleanup_cli.scan_workspace", return_value=protected_scan), \
                contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
            code = run_cleanup(str(self.root))
        self.assertEqual(code, 0)
        self.assertIn("no", output.getvalue().lower())
        self.assertTrue(self.candidate_path.exists())

    def test_json_is_deterministic_and_does_not_leak_capabilities(self) -> None:
        outputs = []
        for _ in range(2):
            output = io.StringIO()
            with patch("dwi.cleanup_cli.scan_workspace", return_value=self.scan), \
                    contextlib.redirect_stdout(output), contextlib.redirect_stderr(io.StringIO()):
                code = run_cleanup(str(self.root), as_json=True)
            self.assertEqual(code, 1)
            outputs.append(output.getvalue())
        self.assertEqual(outputs[0], outputs[1])
        self.assertNotIn("_proof", outputs[0])
        self.assertNotIn("authorization_token", outputs[0])
        self.assertNotIn("capability", outputs[0])
        self.assertIn('"risk_label"', outputs[0])

    def test_partial_result_keeps_per_item_outcomes_and_recovery_ids(self) -> None:
        plan = create_workspace_cleanup_plan(self.scan)
        item = plan.items[0]
        result = CleanupApplicationResult(
            "session-test",
            plan.plan_id,
            CleanupSessionState.PARTIAL,
            None,
            None,
            (CleanupItemResult(
                item.plan_item_id,
                CleanupItemOutcome.RECOVERABLE,
                None,
                "recovery-test",
                "journaled recovery remains available",
            ),),
            None,
            "items were processed independently",
        )
        output = io.StringIO()
        with patch("dwi.cleanup_cli.scan_workspace", return_value=self.scan), \
                patch("dwi.cleanup_cli.execute_cleanup_session", return_value=result), \
                patch("dwi.cleanup_cli.workspace_engine_revalidator", return_value=self._engine_revalidator()), \
                contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
            code = run_cleanup(
                str(self.root),
                confirmation_phrase=CONFIRMATION_PHRASE,
                input_fn=lambda _prompt: "",
            )
        self.assertEqual(code, 4)
        self.assertIn("partial", output.getvalue())
        self.assertIn("recovery-test", output.getvalue())

    def test_undo_invalid_occupied_and_repeated_states_are_safe(self) -> None:
        plan = create_workspace_cleanup_plan(self.scan)
        runtime = workspace_mutation_runtime()
        from dwi.application import create_cleanup_session, create_human_confirmation, execute_cleanup_session
        session = create_cleanup_session(plan)
        confirmation = create_human_confirmation(
            session,
            session.review,
            confirmation_phrase=CONFIRMATION_PHRASE,
            confirmed_at="2026-01-01T00:00:00+00:00",
        )
        from dwi.cleanup_engine import workspace_engine_revalidator
        result = execute_cleanup_session(
            session,
            confirmation,
            engine_revalidator=self._engine_revalidator(),
            mutation_provider=runtime.provider,
        )
        self.assertEqual(result.state, CleanupSessionState.EXECUTED)
        recovery_id = result.item_results[0].recovery_id
        self.assertEqual(_restore_human(runtime, "invalid"), 5)
        self.candidate_path.mkdir()
        self.assertEqual(_restore_human(runtime, recovery_id), 5)
        self.candidate_path.rmdir()
        self.assertEqual(_restore_human(runtime, recovery_id), 0)
        self.assertEqual(_restore_human(runtime, recovery_id), 0)

    def test_keyboard_interrupt_during_scan_returns_cancellation(self) -> None:
        output = io.StringIO()
        with patch("dwi.cleanup_cli.scan_workspace", side_effect=KeyboardInterrupt), \
                contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
            code = run_cleanup(str(self.root))
        self.assertEqual(code, 1)
        self.assertIn("cancelled", output.getvalue())
        self.assertNotIn("Traceback", output.getvalue())
        self._assert_no_new_mutation_state()

    def test_keyboard_interrupt_during_plan_and_review_setup_returns_cancellation(self) -> None:
        for target in ("plan", "review"):
            with self.subTest(target=target):
                output = io.StringIO()
                patch_target = (
                    "dwi.cleanup_cli.create_workspace_cleanup_plan"
                    if target == "plan"
                    else "dwi.cleanup_cli._review_human"
                )
                interrupt_patch = patch(patch_target, side_effect=KeyboardInterrupt)
                with patch("dwi.cleanup_cli.scan_workspace", return_value=self.scan), \
                        interrupt_patch, \
                        contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
                    code = run_cleanup(str(self.root))
                self.assertEqual(code, 1)
                self.assertIn("cancelled", output.getvalue())
                self.assertNotIn("Traceback", output.getvalue())
                self._assert_no_new_mutation_state()

    def test_keyboard_interrupt_during_confirmation_returns_cancellation(self) -> None:
        def interrupt(_prompt):
            raise KeyboardInterrupt

        output = io.StringIO()
        with patch("dwi.cleanup_cli.scan_workspace", return_value=self.scan), \
                contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
            code = run_cleanup(str(self.root), input_fn=interrupt)
        self.assertEqual(code, 1)
        self.assertIn("cancelled", output.getvalue())
        self.assertNotIn("Traceback", output.getvalue())
        self._assert_no_new_mutation_state()

    def test_keyboard_interrupt_during_fresh_revalidation_returns_cancellation(self) -> None:
        def interrupt(_plan):
            raise KeyboardInterrupt

        output = io.StringIO()
        with patch("dwi.cleanup_cli.scan_workspace", return_value=self.scan), \
                patch("dwi.cleanup_cli.workspace_engine_revalidator", return_value=_engine_revalidator(interrupt)), \
                contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
            code = run_cleanup(str(self.root), confirmation_phrase=CONFIRMATION_PHRASE)
        self.assertEqual(code, 1)
        self.assertIn("cancelled", output.getvalue())
        self.assertNotIn("Traceback", output.getvalue())
        self._assert_no_new_mutation_state()

    def test_keyboard_interrupt_after_authorization_preserves_recovery_state(self) -> None:
        output = io.StringIO()
        with patch("dwi.cleanup_cli.scan_workspace", return_value=self.scan), \
                patch("dwi.cleanup_cli.workspace_engine_revalidator", return_value=self._engine_revalidator()), \
                patch("dwi.mutation.os.rename", side_effect=KeyboardInterrupt), \
                contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
            code = run_cleanup(str(self.root), confirmation_phrase=CONFIRMATION_PHRASE)
        self.assertEqual(code, 3)
        self.assertIn("failed", output.getvalue())
        self.assertNotIn("Traceback", output.getvalue())
        self.assertTrue(self.candidate_path.exists())
        self.assertTrue((self.root / ".dwi-quarantine").is_dir())
        self.assertTrue((self.root / ".dwi-journal.jsonl").is_file())
        self.assertTrue(any(name.startswith(".dwi-claim-") for name in self._mutation_state_names()))

    def test_unjournaled_quarantine_entry_blocks_before_revalidation_or_authorization(self) -> None:
        quarantine = self.root / ".dwi-quarantine"
        quarantine.mkdir()
        (quarantine / "unjournaled.bin").write_bytes(b"unaccounted")
        output = io.StringIO()

        def should_not_revalidate(_plan):
            raise AssertionError("untrusted quarantine inventory reached fresh revalidation")

        with patch("dwi.cleanup_cli.scan_workspace", return_value=self.scan), \
                patch("dwi.cleanup_cli.workspace_engine_revalidator", return_value=_engine_revalidator(should_not_revalidate)), \
                contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
            code = run_cleanup(str(self.root), confirmation_phrase=CONFIRMATION_PHRASE)
        self.assertEqual(code, 5)
        self.assertIn("reconciliation", output.getvalue())
        self.assertTrue((quarantine / "unjournaled.bin").exists())
        self.assertFalse((self.root / ".dwi-journal.jsonl").exists())
        self.assertFalse(any(name.startswith(".dwi-claim-") for name in self._mutation_state_names()))

    def test_keyboard_interrupt_inside_authorized_context_is_clean_and_preserves_state(self) -> None:
        import dwi.cleanup_engine as cleanup_engine

        original_create = cleanup_engine.create_quarantine_root

        def create_then_interrupt(*args, **kwargs):
            original_create(*args, **kwargs)
            raise KeyboardInterrupt

        output = io.StringIO()
        with patch("dwi.cleanup_cli.scan_workspace", return_value=self.scan), \
                patch("dwi.cleanup_cli.workspace_engine_revalidator", return_value=self._engine_revalidator()), \
                patch("dwi.cleanup_engine.create_quarantine_root", side_effect=create_then_interrupt), \
                contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
            code = run_cleanup(str(self.root), confirmation_phrase=CONFIRMATION_PHRASE)
        self.assertEqual(code, 1)
        self.assertIn("cancelled", output.getvalue())
        self.assertNotIn("Traceback", output.getvalue())
        self.assertTrue((self.root / ".dwi-quarantine").is_dir())
        self.assertFalse((self.root / ".dwi-journal.jsonl").exists())
        self.assertTrue(self.candidate_path.exists())

    def test_raw_path_mutation_and_unsafe_bypass_commands_are_unavailable(self) -> None:
        for argv in (
            ["delete", str(self.candidate_path)],
            ["remove", str(self.candidate_path)],
            ["quarantine", str(self.candidate_path)],
            ["cleanup", str(self.root), "--force"],
            ["cleanup", str(self.root), "--yes"],
        ):
            with self.subTest(argv=argv), self.assertRaises(SystemExit) as context:
                main(argv)
            self.assertEqual(context.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
