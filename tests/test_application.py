import dataclasses
import inspect
import os
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
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
    FilesystemIdentity,
    Finding,
    NodeKind,
    ObservationStatus,
    ObservedNode,
    ProtectionClass,
    Provenance,
    PytestCacheInterpretation,
    ReachabilityState,
    RegenerabilityState,
    RegenerationCost,
    RiskLabel,
    RootBoundary,
    RootObservation,
    RootScope,
    RootStatus,
    ScanTermination,
    SizeObservation,
    SystemScan,
    QuarantineState,
    evaluate_safety,
    scan_context_from_system_scan,
)
from dwi.application import (
    CleanupItemOutcome,
    CleanupSessionState,
    EngineRevalidator,
    HumanConfirmation,
    TrustedSnapshotSet,
    _engine_revalidator,
    _trusted_snapshot_set,
    create_cleanup_session,
    create_human_confirmation,
    execute_cleanup_session,
)
from dwi.cleanup import _digest
from dwi.mutation import (
    _authoritative_path,
    _claim_authorization_item,
    create_audit_journal,
    create_disposable_root,
    create_quarantine_root,
    reconcile_pending_operations,
    restore_recovery,
)
from dwi.policy import SafetyContext


class CleanupApplicationTests(unittest.TestCase):
    def setUp(self) -> None:
        if os.name != "nt":
            self.skipTest("application mutation integration is Windows-only")
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        base = Path(self.temporary.name)
        (base / ".dwi-disposable-root").write_text("DWI-DISPOSABLE-ROOT-v0.3\n", encoding="utf-8")
        self.workspace = base / "workspace"
        self.workspace.mkdir()
        (base / ".dwi-quarantine").mkdir()
        self.disposable = create_disposable_root(base)
        self.quarantine_root = create_quarantine_root(self.disposable)
        self.journal = create_audit_journal(self.disposable)
        self.clock = lambda: "2026-01-01T00:00:00.000000Z"

    def _context(self, status: RootStatus = RootStatus.COMPLETE):
        root = str(self.workspace)
        scan = SystemScan(
            requested_roots=(root,),
            root_observations=(RootObservation(
                root, RootScope.ADDITIONAL_LOCAL, "workspace", RootBoundary.LOCAL_DIRECTORY,
                status, "synthetic",
            ),),
            workspace_findings=(), global_storage_findings=(), git_observations=(),
            observation_failures=(), ambiguous_boundaries=(),
            termination=ScanTermination.COMPLETED, nodes_observed=1, files_observed=0,
        )
        return scan_context_from_system_scan(scan)

    def _finding(self, path: Path) -> Finding:
        evidence = Evidence(
            "provenance", "synthetic-application-fixture",
            "Synthetic high-confidence provenance evidence.", ObservationStatus.OBSERVED,
            EvidencePolarity.SUPPORTS, Confidence.HIGH, "pytest",
        )
        bundle = EvidenceBundle((evidence,), (EvidenceRequirement("provenance", Confidence.HIGH),))
        candidate = CleanupCandidate(
            ObservedNode(str(path), NodeKind.DIRECTORY, ProtectionClass.ORDINARY), bundle,
        )
        selection = CandidateSelection(CandidateEligibility.SELECTED, bundle, candidate)
        interpretation = PytestCacheInterpretation(
            Provenance("python", "pytest", Confidence.HIGH, ("provenance",)),
            RegenerabilityState.REPRODUCIBLE, RegenerationCost.LOW,
            ReachabilityState.CONFIRMED_UNREFERENCED, ActivityState.INACTIVE,
            ProtectionClass.ORDINARY,
        )
        decision = evaluate_safety(SafetyContext(
            candidate=candidate, evidence=bundle, provenance=interpretation.provenance,
            regenerability=interpretation.regenerability,
            regeneration_cost=interpretation.regeneration_cost,
            reachability=interpretation.reachability,
            activity=interpretation.activity, protection=interpretation.protection,
        ))
        return Finding(ArtifactKind.PYTEST_CACHE, str(path), bundle, interpretation, selection, decision, SizeObservation(10, True))

    def _identity(self, path: Path, inode: int | None = None) -> FilesystemIdentity:
        metadata = os.lstat(path)
        authority = _authoritative_path(str(path))
        self.assertIsNotNone(authority)
        return FilesystemIdentity(
            metadata.st_dev, inode or metadata.st_ino, NodeKind.DIRECTORY, False, authority.final_path,
        )

    def _plan(self, paths: tuple[Path, ...] | None = None):
        paths = paths or (self.workspace / ".pytest_cache",)
        for path in paths:
            path.mkdir(parents=True, exist_ok=True)
        context = self._context()
        from dwi import create_cleanup_plan
        findings = tuple(self._finding(path) for path in paths)
        return create_cleanup_plan(
            findings,
            filesystem_identities={str(path): self._identity(path) for path in paths},
            scan_context=context,
            approved_root=context.approved_roots[0],
        )

    def _session_and_confirmation(self, plan):
        session = create_cleanup_session(plan)
        confirmation = create_human_confirmation(
            session,
            session.review,
            confirmation_phrase="I reviewed this exact cleanup plan.",
            confirmed_at=self.clock(),
        )
        return session, confirmation

    def _execute(self, session, confirmation, *, snapshots=None, context=None, engine_revalidator=None):
        snapshots = snapshots or {item.plan_item_id: item.snapshot for item in session.plan.items}
        context = context or self._context()
        engine_revalidator = engine_revalidator or _engine_revalidator(
            lambda plan: _trusted_snapshot_set(
                plan,
                snapshots,
                context,
                engine_version="synthetic-engine-v0.3",
                created_at=self.clock(),
            )
        )
        return execute_cleanup_session(
            session,
            confirmation,
            engine_revalidator=engine_revalidator,
            mutation_root=self.disposable,
            quarantine_root=self.quarantine_root,
            journal=self.journal,
            clock=self.clock,
        )

    def test_confirmation_is_exact_and_not_a_boolean(self) -> None:
        plan = self._plan()
        session, confirmation = self._session_and_confirmation(plan)
        self.assertTrue(session.is_engine_bound)
        self.assertTrue(confirmation.is_engine_bound)
        forged = HumanConfirmation(
            session.session_id, plan.plan_id, session.review.plan_digest,
            session.review.review_digest, session.review.reviewed_item_ids,
            "yes", self.clock(), "forged",
        )
        result = self._execute(session, forged)
        self.assertEqual(result.state, CleanupSessionState.BLOCKED)
        self.assertTrue(Path(plan.items[0].snapshot.path).exists())
        self.assertEqual(self._execute(session, None).state, CleanupSessionState.BLOCKED)

    def test_different_modified_and_stale_confirmation_is_blocked(self) -> None:
        plan = self._plan()
        session, confirmation = self._session_and_confirmation(plan)
        other_plan = self._plan((self.workspace / "other-cache",))
        other_session, other_confirmation = self._session_and_confirmation(other_plan)
        self.assertEqual(self._execute(session, other_confirmation).state, CleanupSessionState.BLOCKED)
        self.assertEqual(
            self._execute(session, dataclasses.replace(confirmation, review_digest="stale")).state,
            CleanupSessionState.BLOCKED,
        )
        modified_session = dataclasses.replace(session, plan=other_plan)
        with self.assertRaises(TypeError):
            self._execute(modified_session, confirmation)
        self.assertTrue(other_session.is_engine_bound)

    def test_post_confirmation_filesystem_and_policy_changes_block(self) -> None:
        plan = self._plan()
        session, confirmation = self._session_and_confirmation(plan)
        item = plan.items[0]
        changed_size = dataclasses.replace(item.snapshot, size=SizeObservation(11, True))
        result = self._execute(session, confirmation, snapshots={item.plan_item_id: changed_size})
        self.assertEqual(result.validation_status.value, "stale_changed")
        self.assertEqual(result.state, CleanupSessionState.BLOCKED)
        changed_policy = dataclasses.replace(
            item.snapshot,
            risk_label=RiskLabel.REVIEW_REQUIRED,
            action_eligibility=ActionEligibility.REQUIRES_REVIEW,
        )
        result = self._execute(session, confirmation, snapshots={item.plan_item_id: changed_policy})
        self.assertEqual(result.validation_status.value, "blocked")
        self.assertEqual(result.state, CleanupSessionState.BLOCKED)
        for field, value in (
            ("provenance", Provenance("python", "other-tool", Confidence.HIGH, ("provenance",))),
            ("regenerability", RegenerabilityState.UNKNOWN),
            ("regeneration_cost", RegenerationCost.UNKNOWN),
            ("activity", ActivityState.ACTIVE_RUNTIME),
            ("reachability", ReachabilityState.CONFIRMED_REFERENCED),
            ("protection", ProtectionClass.PROTECTED),
        ):
            with self.subTest(field=field):
                changed = dataclasses.replace(item.snapshot, **{field: value})
                result = self._execute(session, confirmation, snapshots={item.plan_item_id: changed})
                self.assertEqual(result.state, CleanupSessionState.BLOCKED)
                self.assertTrue(Path(item.snapshot.path).exists())
        changed_evidence = dataclasses.replace(item.snapshot, evidence=EvidenceBundle((), ()))
        result = self._execute(session, confirmation, snapshots={item.plan_item_id: changed_evidence})
        self.assertEqual(result.state, CleanupSessionState.BLOCKED)

    def test_fresh_state_requires_engine_bound_revalidator_and_exact_plan(self) -> None:
        plan = self._plan()
        session, confirmation = self._session_and_confirmation(plan)
        item = plan.items[0]

        rejected_mapping = self._execute(session, confirmation, engine_revalidator={item.plan_item_id: item.snapshot})
        self.assertEqual(rejected_mapping.state, CleanupSessionState.BLOCKED)
        self.assertIn("revalidation capability", rejected_mapping.reason or "")

        hand_constructed = TrustedSnapshotSet(
            plan.plan_id,
            "replayed-plan-digest",
            (item.plan_item_id,),
            "synthetic-engine-v0.3",
            self._context().scan_provenance,
            "replayed-digest",
            "replayed-evaluation",
            self.clock(),
            ((item.plan_item_id, item.snapshot),),
            self._context(),
        )
        self.assertFalse(hand_constructed.is_engine_bound)
        forged_revalidator = EngineRevalidator(lambda _: hand_constructed)
        forged_result = self._execute(session, confirmation, engine_revalidator=forged_revalidator)
        self.assertEqual(forged_result.state, CleanupSessionState.BLOCKED)
        self.assertIn("fresh engine revalidation", forged_result.reason or "")

        failing_revalidator = _engine_revalidator(
            lambda _: (_ for _ in ()).throw(RuntimeError("synthetic engine observation failure"))
        )
        failed_result = self._execute(session, confirmation, engine_revalidator=failing_revalidator)
        self.assertEqual(failed_result.state, CleanupSessionState.BLOCKED)
        self.assertIn("fresh engine revalidation", failed_result.reason or "")

        other_plan = self._plan((self.workspace / "other-cache",))
        other_snapshots = {other_plan.items[0].plan_item_id: other_plan.items[0].snapshot}
        wrong_plan_revalidator = _engine_revalidator(
            lambda _: _trusted_snapshot_set(
                other_plan,
                other_snapshots,
                self._context(),
                engine_version="synthetic-engine-v0.3",
                created_at=self.clock(),
            )
        )
        wrong_plan_result = self._execute(session, confirmation, engine_revalidator=wrong_plan_revalidator)
        self.assertEqual(wrong_plan_result.state, CleanupSessionState.BLOCKED)
        self.assertIn("fresh engine revalidation", wrong_plan_result.reason or "")

    def test_application_requests_fresh_engine_evaluation_after_confirmation(self) -> None:
        plan = self._plan()
        session, confirmation = self._session_and_confirmation(plan)
        calls = []

        def revalidate(current_plan):
            calls.append(current_plan)
            return _trusted_snapshot_set(
                current_plan,
                {item.plan_item_id: item.snapshot for item in current_plan.items},
                self._context(),
                engine_version="synthetic-engine-v0.3",
                created_at=self.clock(),
            )

        result = self._execute(session, confirmation, engine_revalidator=_engine_revalidator(revalidate))
        self.assertEqual(result.state, CleanupSessionState.EXECUTED)
        self.assertEqual(calls, [plan])

    def test_partial_or_failed_scan_blocks_after_confirmation(self) -> None:
        plan = self._plan()
        session, confirmation = self._session_and_confirmation(plan)
        for status in (RootStatus.PARTIAL, RootStatus.FAILED):
            with self.subTest(status=status):
                result = self._execute(session, confirmation, context=self._context(status))
                self.assertEqual(result.state, CleanupSessionState.BLOCKED)
                self.assertTrue(Path(plan.items[0].snapshot.path).exists())

    def test_orphan_claim_reconciles_metadata_then_stops_before_new_execution(self) -> None:
        plan = self._plan()
        session, confirmation = self._session_and_confirmation(plan)
        item = plan.items[0]
        from dwi.cleanup import authorize_execution, validate_cleanup_plan
        validation = validate_cleanup_plan(
            plan,
            {item.plan_item_id: item.snapshot},
            scan_context=self._context(),
        )
        authorization = authorize_execution(plan, validation)
        destination = self.quarantine_root.path + "\\" + f"recovery-{_digest((plan.plan_id, item.plan_item_id))[:32]}"
        claimed, reason = _claim_authorization_item(
            self.journal,
            plan,
            item,
            authorization,
            validation_identity=validation.validation_token,
            quarantine_path=destination,
            timestamp=self.clock(),
        )
        self.assertTrue(claimed, reason)
        self.assertEqual(self.journal.read_entries(), ())
        claim_files_before = tuple(sorted(
            path.name for path in Path(self.disposable.path).iterdir()
            if path.name.startswith(".dwi-claim-")
        ))
        quarantine_entries_before = tuple(Path(self.quarantine_root.path).iterdir())
        fresh_calls: list[object] = []

        def revalidate(current_plan):
            fresh_calls.append(current_plan)
            return _trusted_snapshot_set(
                current_plan,
                {current_item.plan_item_id: current_item.snapshot for current_item in current_plan.items},
                self._context(),
                engine_version="synthetic-engine-v0.3",
                created_at=self.clock(),
            )

        with patch("dwi.application.authorize_execution", side_effect=AssertionError("new authorization was issued")):
            result = self._execute(session, confirmation, engine_revalidator=_engine_revalidator(revalidate))
        self.assertEqual(result.state, CleanupSessionState.RECONCILIATION_REQUIRED)
        self.assertEqual(fresh_calls, [])
        self.assertIsNotNone(result.reconciliation)
        self.assertTrue(result.reconciliation.metadata_appended)
        self.assertEqual(
            [entry.status for entry in self.journal.read_entries()],
            [QuarantineState.AUTHORIZATION_CLAIMED, QuarantineState.FAILED],
        )
        self.assertEqual(tuple(sorted(
            path.name for path in Path(self.disposable.path).iterdir()
            if path.name.startswith(".dwi-claim-")
        )), claim_files_before)
        self.assertEqual(tuple(Path(self.quarantine_root.path).iterdir()), quarantine_entries_before)
        self.assertTrue(Path(item.snapshot.path).exists())

        journal_after = Path(self.journal.path).read_bytes() if Path(self.journal.path).exists() else b""
        repeated = reconcile_pending_operations(self.journal, self.disposable, self.quarantine_root, clock=self.clock)
        self.assertEqual(repeated.claim_recoveries, ())
        self.assertFalse(repeated.metadata_appended)
        self.assertEqual(Path(self.journal.path).read_bytes(), journal_after)

    def test_successful_execution_reports_per_item_and_undo_remains_available(self) -> None:
        plan = self._plan()
        session, confirmation = self._session_and_confirmation(plan)
        result = self._execute(session, confirmation)
        self.assertEqual(result.state, CleanupSessionState.EXECUTED)
        self.assertFalse(result.transactional)
        self.assertEqual(result.item_results[0].outcome, CleanupItemOutcome.SUCCEEDED)
        restored = restore_recovery(
            result.item_results[0].recovery_id,
            self.journal,
            self.disposable,
            self.quarantine_root,
            clock=self.clock,
        )
        self.assertEqual(restored.state.value, "restored")

    def test_replayed_execution_cannot_execute_again(self) -> None:
        plan = self._plan()
        session, confirmation = self._session_and_confirmation(plan)
        first = self._execute(session, confirmation)
        second = self._execute(session, confirmation)
        self.assertEqual(first.state, CleanupSessionState.EXECUTED)
        self.assertNotEqual(second.state, CleanupSessionState.EXECUTED)
        self.assertEqual(second.item_results[0].outcome, CleanupItemOutcome.FAILED)

    def test_concurrent_execution_has_at_most_one_winner(self) -> None:
        plan = self._plan()
        session, confirmation = self._session_and_confirmation(plan)
        with ThreadPoolExecutor(max_workers=2) as executor:
            results = tuple(executor.map(lambda _: self._execute(session, confirmation), (1, 2)))
        self.assertEqual(sum(result.state is CleanupSessionState.EXECUTED for result in results), 1)
        self.assertEqual(sum(result.state is CleanupSessionState.EXECUTED for result in results), 1)

    def test_partial_multi_item_execution_is_explicitly_non_transactional(self) -> None:
        plan = self._plan((self.workspace / "first-cache", self.workspace / "second-cache"))
        collision_item = plan.items[-1]
        collision = self.quarantine_root.path + "\\" + f"recovery-{_digest((plan.plan_id, collision_item.plan_item_id))[:32]}"
        Path(collision).mkdir()
        session, confirmation = self._session_and_confirmation(plan)
        result = self._execute(session, confirmation)
        self.assertEqual(result.state, CleanupSessionState.RECONCILIATION_REQUIRED)
        self.assertFalse(result.transactional)
        self.assertEqual({item.outcome for item in result.item_results}, {CleanupItemOutcome.BLOCKED})

    def test_unexpected_multi_item_failure_preserves_completed_item_and_undo(self) -> None:
        plan = self._plan((self.workspace / "first-cache", self.workspace / "second-cache"))
        session, confirmation = self._session_and_confirmation(plan)
        second_path = plan.items[-1].snapshot.path
        import dwi.mutation as mutation_module
        original_validate = mutation_module._validate_plan_item_before_move

        def inject_failure(current_plan, item_path, *args, **kwargs):
            if item_path == second_path:
                raise RuntimeError("injected unexpected item failure")
            return original_validate(current_plan, item_path, *args, **kwargs)

        with patch("dwi.mutation._validate_plan_item_before_move", side_effect=inject_failure):
            result = self._execute(session, confirmation)
        self.assertEqual(result.state, CleanupSessionState.PARTIAL)
        first_result = result.item_results[0]
        second_result = result.item_results[1]
        self.assertEqual(first_result.outcome, CleanupItemOutcome.SUCCEEDED)
        self.assertIn(second_result.outcome, {CleanupItemOutcome.BLOCKED, CleanupItemOutcome.FAILED})
        restored = restore_recovery(
            first_result.recovery_id,
            self.journal,
            self.disposable,
            self.quarantine_root,
            clock=self.clock,
        )
        self.assertEqual(restored.state.value, "restored")

    def test_quarantine_failure_and_orphan_claim_require_review(self) -> None:
        plan = self._plan()
        item = plan.items[0]
        collision = self.quarantine_root.path + "\\" + f"recovery-{_digest((plan.plan_id, item.plan_item_id))[:32]}"
        Path(collision).mkdir()
        session, confirmation = self._session_and_confirmation(plan)
        result = self._execute(session, confirmation)
        self.assertEqual(result.state, CleanupSessionState.RECONCILIATION_REQUIRED)
        self.assertEqual(result.item_results[0].outcome, CleanupItemOutcome.BLOCKED)

        plan = self._plan((self.workspace / "orphan-cache",))
        session, confirmation = self._session_and_confirmation(plan)
        item = plan.items[0]
        validation_context = self._context()
        from dwi.cleanup import validate_cleanup_plan
        validation = validate_cleanup_plan(plan, {item.plan_item_id: item.snapshot}, scan_context=validation_context)
        from dwi.cleanup import authorize_execution
        authorization = authorize_execution(plan, validation)
        claimed, reason = _claim_authorization_item(
            self.journal,
            plan,
            item,
            authorization,
            validation_identity=validation.validation_token,
            quarantine_path=self.quarantine_root.path + "\\" + f"recovery-{_digest((plan.plan_id, item.plan_item_id))[:32]}",
            timestamp=self.clock(),
        )
        self.assertTrue(claimed, reason)
        orphan_result = self._execute(session, confirmation)
        self.assertEqual(orphan_result.state, CleanupSessionState.RECONCILIATION_REQUIRED)
        self.assertTrue(Path(item.snapshot.path).exists())

    def test_no_public_or_raw_path_application_api(self) -> None:
        import dwi
        self.assertFalse(hasattr(dwi, "execute_cleanup_session"))
        self.assertFalse(hasattr(dwi, "create_human_confirmation"))
        self.assertNotIn("path", inspect.signature(execute_cleanup_session).parameters)
        plan = self._plan()
        session, confirmation = self._session_and_confirmation(plan)
        with self.assertRaises(TypeError):
            execute_cleanup_session(
                session,
                confirmation,
                current_snapshots={},  # type: ignore[call-arg]
                scan_context=self._context(),  # type: ignore[call-arg]
                mutation_root=self.disposable,
                quarantine_root=self.quarantine_root,
                journal=self.journal,
                clock=self.clock,
            )


if __name__ == "__main__":
    unittest.main()
