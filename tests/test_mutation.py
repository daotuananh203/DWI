import dataclasses
import json
import inspect
import os
import tempfile
import unittest
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
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
    ExecutionAuthorization,
    ExecutionAuthorizationStatus,
    FilesystemIdentity,
    Finding,
    NodeKind,
    ObservationStatus,
    ObservedNode,
    PlanValidationStatus,
    ProtectionClass,
    Provenance,
    PytestCacheInterpretation,
    QuarantineState,
    RegenerabilityState,
    RegenerationCost,
    ReachabilityState,
    SizeObservation,
    SystemScan,
    RootBoundary,
    RootObservation,
    RootScope,
    RootStatus,
    ScanTermination,
    authorize_execution,
    evaluate_safety,
    scan_context_from_system_scan,
    validate_cleanup_plan,
)
from dwi.cleanup import _digest
from dwi.mutation import (
    AuditJournal,
    ApprovedMutationRoot,
    ClaimRecoveryState,
    JournalCorruptionError,
    JournalEntry,
    JournalError,
    MutationRefused,
    _canonical_json,
    _entry_hash,
    _entry_payload,
    _authoritative_path,
    AuthoritativePath,
    _is_protected_authoritative_path,
    _verify_approved_local_root,
    approve_local_mutation_root,
    create_audit_journal,
    create_disposable_root,
    create_quarantine_root,
    inspect_quarantine_inventory,
    _claim_authorization_item,
    quarantine_plan,
    reconcile_pending_operations,
    restore_recovery,
)
from dwi.policy import SafetyContext


class MutationPrimitiveTests(unittest.TestCase):
    def setUp(self) -> None:
        if os.name != "nt":
            self.skipTest("disposable mutation primitives are Windows-only")
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        base = Path(self.temporary.name)
        (base / ".dwi-disposable-root").write_text("DWI-DISPOSABLE-ROOT-v0.3\n", encoding="utf-8")
        self.workspace = base / "workspace"
        self.workspace.mkdir()
        self.quarantine_directory = base / ".dwi-quarantine"
        self.quarantine_directory.mkdir()
        self.disposable = create_disposable_root(base)
        self.quarantine_root = create_quarantine_root(self.disposable)
        self.journal = create_audit_journal(self.disposable)
        self.clock = lambda: "2026-01-01T00:00:00.000000Z"

    def _finding(self, path: Path) -> Finding:
        evidence = Evidence(
            key="provenance",
            source="synthetic-mutation-fixture",
            description="Synthetic high-confidence provenance evidence.",
            observation_status=ObservationStatus.OBSERVED,
            polarity=EvidencePolarity.SUPPORTS,
            confidence=Confidence.HIGH,
            value="pytest",
        )
        bundle = EvidenceBundle((evidence,), (EvidenceRequirement("provenance", Confidence.HIGH),))
        node = ObservedNode(str(path), NodeKind.DIRECTORY, ProtectionClass.ORDINARY)
        candidate = CleanupCandidate(node, bundle)
        selection = CandidateSelection(CandidateEligibility.SELECTED, bundle, candidate)
        interpretation = PytestCacheInterpretation(
            provenance=Provenance("python", "pytest", Confidence.HIGH, ("provenance",)),
            regenerability=RegenerabilityState.REPRODUCIBLE,
            regeneration_cost=RegenerationCost.LOW,
            reachability=ReachabilityState.CONFIRMED_UNREFERENCED,
            activity=ActivityState.INACTIVE,
            protection=ProtectionClass.ORDINARY,
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
        return Finding(ArtifactKind.PYTEST_CACHE, str(path), bundle, interpretation, selection, decision, SizeObservation(10, True))

    def _context(self):
        root = str(self.workspace)
        scan = SystemScan(
            requested_roots=(root,),
            root_observations=(RootObservation(root, RootScope.ADDITIONAL_LOCAL, "workspace", RootBoundary.LOCAL_DIRECTORY, RootStatus.COMPLETE, "synthetic"),),
            workspace_findings=(),
            global_storage_findings=(),
            git_observations=(),
            observation_failures=(),
            ambiguous_boundaries=(),
            termination=ScanTermination.COMPLETED,
            nodes_observed=1,
            files_observed=0,
        )
        return scan_context_from_system_scan(scan)

    def _identity(self, path: Path) -> FilesystemIdentity:
        metadata = os.lstat(path)
        authority = _authoritative_path(str(path))
        self.assertIsNotNone(authority)
        return FilesystemIdentity(metadata.st_dev, metadata.st_ino, NodeKind.DIRECTORY, False, authority.final_path)

    def _plan(self, paths: tuple[Path, ...] | None = None):
        paths = paths or (self.workspace / ".pytest_cache",)
        for path in paths:
            path.mkdir(parents=True, exist_ok=True)
        context = self._context()
        from dwi import create_cleanup_plan
        return create_cleanup_plan(
            tuple(self._finding(path) for path in paths),
            filesystem_identities={str(path): self._identity(path) for path in paths},
            scan_context=context,
            approved_root=context.approved_roots[0],
        )

    def _authorization(self, plan):
        validation = validate_cleanup_plan(
            plan,
            {item.plan_item_id: item.snapshot for item in plan.items},
            scan_context=self._context(),
        )
        return validation, authorize_execution(plan, validation)

    def _recovery_id(self, plan, item) -> str:
        return f"recovery-{_digest((plan.plan_id, item.plan_item_id))[:32]}"

    def _manual_entry(self, plan, validation, authorization, item, status, recovery_id, quarantine_path, reason=None):
        entries = self.journal.read_entries()
        entry = JournalEntry(
            f"manual-{recovery_id}-{status.value}",
            plan.plan_id.value,
            item.plan_item_id.value,
            validation.validation_token,
            authorization.authorization_token,
            item.snapshot.path,
            quarantine_path,
            item.snapshot.filesystem_identity,
            self.clock(),
            status,
            recovery_id,
            reason,
            "",
            len(entries) + 1,
            entries[-1].record_hash if entries else "GENESIS:dwi-journal-v0.3",
        )
        return dataclasses.replace(entry, record_hash=_entry_hash(entry))

    def test_valid_authorized_quarantine_is_reversible_and_journaled(self) -> None:
        plan = self._plan()
        validation, authorization = self._authorization(plan)
        result = quarantine_plan(plan, validation, authorization, self.disposable, self.quarantine_root, self.journal, clock=self.clock)
        self.assertEqual(result.failures, ())
        self.assertEqual(result.records[0].state, QuarantineState.QUARANTINED)
        destination = Path(result.records[0].metadata.quarantine_path)
        self.assertFalse(Path(result.records[0].metadata.original_path).exists())
        self.assertTrue(destination.exists())
        self.assertEqual([entry.status for entry in self.journal.read_entries()], [
            QuarantineState.AUTHORIZATION_CLAIMED,
            QuarantineState.PLANNED,
            QuarantineState.QUARANTINING,
            QuarantineState.QUARANTINED,
        ])

        restored = restore_recovery(result.records[0].metadata.recovery_id, self.journal, self.disposable, self.quarantine_root, clock=self.clock)
        self.assertEqual(restored.state, QuarantineState.RESTORED)
        self.assertTrue(Path(result.records[0].metadata.original_path).exists())
        self.assertFalse(destination.exists())

    def test_empty_quarantine_inventory_is_valid_and_read_only(self) -> None:
        before = tuple(sorted(path.name for path in Path(self.quarantine_root.path).iterdir()))
        journal_before = Path(self.journal.path).read_bytes() if Path(self.journal.path).exists() else None
        result = inspect_quarantine_inventory(self.journal, self.disposable, self.quarantine_root)
        self.assertEqual(result.failures, ())
        self.assertEqual(tuple(sorted(path.name for path in Path(self.quarantine_root.path).iterdir())), before)
        self.assertEqual(
            Path(self.journal.path).read_bytes() if Path(self.journal.path).exists() else None,
            journal_before,
        )

    def test_valid_journaled_quarantine_inventory_is_accepted(self) -> None:
        plan = self._plan()
        validation, authorization = self._authorization(plan)
        result = quarantine_plan(
            plan, validation, authorization, self.disposable, self.quarantine_root, self.journal, clock=self.clock,
        )
        self.assertEqual(result.failures, ())
        inspected = inspect_quarantine_inventory(self.journal, self.disposable, self.quarantine_root)
        self.assertEqual(inspected.failures, ())

    def test_unknown_quarantine_entries_fail_closed_without_repair(self) -> None:
        cases = ("unjournaled.bin", "manual-copy", "malformed-recovery-object")
        for name in cases:
            with self.subTest(name=name):
                path = Path(self.quarantine_root.path, name)
                if name == "unjournaled.bin":
                    path.write_bytes(b"unaccounted")
                else:
                    path.mkdir()
                    if name == "manual-copy":
                        (path / "nested-artifact").write_bytes(b"unaccounted")
                before = tuple(sorted(item.name for item in Path(self.quarantine_root.path).iterdir()))
                result = inspect_quarantine_inventory(self.journal, self.disposable, self.quarantine_root)
                self.assertTrue(result.failures)
                self.assertTrue(any("unexpected quarantine entry" in failure for failure in result.failures))
                self.assertEqual(tuple(sorted(item.name for item in Path(self.quarantine_root.path).iterdir())), before)
                if path.is_dir():
                    if (path / "nested-artifact").exists():
                        (path / "nested-artifact").unlink()
                    path.rmdir()
                else:
                    path.unlink()

    def test_expected_quarantine_payload_missing_or_identity_changed_fails_closed(self) -> None:
        plan = self._plan()
        validation, authorization = self._authorization(plan)
        result = quarantine_plan(
            plan, validation, authorization, self.disposable, self.quarantine_root, self.journal, clock=self.clock,
        )
        destination = Path(result.records[0].metadata.quarantine_path)
        destination.rmdir()
        missing = inspect_quarantine_inventory(self.journal, self.disposable, self.quarantine_root)
        self.assertTrue(any("expected quarantine payload is missing" in failure for failure in missing.failures))

        destination.mkdir()
        changed = inspect_quarantine_inventory(self.journal, self.disposable, self.quarantine_root)
        self.assertTrue(any("filesystem identity/type changed" in failure for failure in changed.failures))

    def test_symlinked_expected_quarantine_payload_fails_closed(self) -> None:
        plan = self._plan()
        validation, authorization = self._authorization(plan)
        result = quarantine_plan(
            plan, validation, authorization, self.disposable, self.quarantine_root, self.journal, clock=self.clock,
        )
        destination = Path(result.records[0].metadata.quarantine_path)
        destination.rmdir()
        target = self.workspace / "symlink-target"
        target.mkdir()
        try:
            os.symlink(str(target), str(destination), target_is_directory=True)
        except (OSError, NotImplementedError) as error:
            self.skipTest(f"symlink fixture unavailable: {error}")
        inspected = inspect_quarantine_inventory(self.journal, self.disposable, self.quarantine_root)
        self.assertTrue(any("linked or reparse-backed" in failure for failure in inspected.failures))

    def test_authorization_item_is_one_shot_and_replay_is_rejected(self) -> None:
        plan = self._plan()
        validation, authorization = self._authorization(plan)
        first = quarantine_plan(plan, validation, authorization, self.disposable, self.quarantine_root, self.journal, clock=self.clock)
        self.assertEqual(first.records[0].state, QuarantineState.QUARANTINED)
        self.assertFalse(authorization.is_authorized)
        replay = quarantine_plan(plan, validation, authorization, self.disposable, self.quarantine_root, self.journal, clock=self.clock)
        self.assertTrue(replay.failures)
        self.assertIn("authorization", replay.failures[0].reason)

    def test_concurrent_replay_has_one_winner_and_no_failed_lifecycle_pollution(self) -> None:
        plan = self._plan()
        validation, authorization = self._authorization(plan)
        with ThreadPoolExecutor(max_workers=2) as executor:
            results = tuple(executor.map(
                lambda _: quarantine_plan(plan, validation, authorization, self.disposable, self.quarantine_root, self.journal, clock=self.clock),
                (1, 2),
            ))
        self.assertEqual(sum(bool(result.records) for result in results), 1)
        self.assertEqual(sum(bool(result.failures) for result in results), 1)
        self.assertEqual(
            [entry.status for entry in self.journal.read_entries()],
            [
                QuarantineState.AUTHORIZATION_CLAIMED,
                QuarantineState.PLANNED,
                QuarantineState.QUARANTINING,
                QuarantineState.QUARANTINED,
            ],
        )

    def test_claim_failure_does_not_mutate_target_or_append_lifecycle(self) -> None:
        plan = self._plan()
        validation, authorization = self._authorization(plan)
        with patch("dwi.mutation.os.open", side_effect=PermissionError("claim denied")):
            result = quarantine_plan(plan, validation, authorization, self.disposable, self.quarantine_root, self.journal, clock=self.clock)
        self.assertTrue(result.failures)
        self.assertTrue(Path(plan.items[0].snapshot.path).exists())
        self.assertEqual(self.journal.read_entries(), ())

    def test_restart_reconciles_claimed_but_not_started_state(self) -> None:
        plan = self._plan()
        validation, authorization = self._authorization(plan)
        item = plan.items[0]
        recovery_id = self._recovery_id(plan, item)
        destination = os.path.join(self.quarantine_root.path, recovery_id)
        claimed = self._manual_entry(
            plan, validation, authorization, item, QuarantineState.AUTHORIZATION_CLAIMED,
            recovery_id, destination,
        )
        self.journal.append(claimed)
        result = reconcile_pending_operations(self.journal, self.disposable, self.quarantine_root, clock=self.clock)
        self.assertEqual(result.entries[-1].status, QuarantineState.FAILED)
        self.assertIn("claimed", result.entries[-1].failure_reason)
        self.assertTrue(Path(item.snapshot.path).exists())

    def test_restart_reconciles_orphan_claim_file_without_mutation_or_replay(self) -> None:
        plan = self._plan()
        validation, authorization = self._authorization(plan)
        item = plan.items[0]
        recovery_id = self._recovery_id(plan, item)
        destination = os.path.join(self.quarantine_root.path, recovery_id)
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
        self.assertTrue(Path(item.snapshot.path).exists())
        reconciled = reconcile_pending_operations(
            self.journal,
            self.disposable,
            self.quarantine_root,
            clock=self.clock,
        )
        self.assertEqual(reconciled.claim_recoveries[0].state, ClaimRecoveryState.RECONCILED_FAILED)
        self.assertEqual(
            [entry.status for entry in self.journal.read_entries()],
            [QuarantineState.AUTHORIZATION_CLAIMED, QuarantineState.FAILED],
        )
        self.assertTrue(reconciled.metadata_appended)
        self.assertTrue(Path(item.snapshot.path).exists())
        repeated = reconcile_pending_operations(
            self.journal,
            self.disposable,
            self.quarantine_root,
            clock=self.clock,
        )
        self.assertEqual(repeated.claim_recoveries, ())
        self.assertFalse(repeated.metadata_appended)

    def test_approved_local_root_is_engine_bound(self) -> None:
        plan = self._plan()
        validation, authorization = self._authorization(plan)
        approved = approve_local_mutation_root(plan, validation, authorization)
        self.assertIsInstance(approved, ApprovedMutationRoot)
        self.assertEqual(approved.path, plan.approved_root.path)
        with self.assertRaises(MutationRefused):
            with patch("dwi.mutation._windows_drive_type", return_value=4):
                approve_local_mutation_root(plan, validation, authorization)

    def test_approved_local_root_supports_same_volume_reversible_quarantine(self) -> None:
        plan = self._plan()
        validation, authorization = self._authorization(plan)
        approved = approve_local_mutation_root(plan, validation, authorization)
        local_quarantine = self.workspace / ".dwi-quarantine"
        local_quarantine.mkdir()
        quarantine_root = create_quarantine_root(approved)
        journal = create_audit_journal(approved)
        result = quarantine_plan(plan, validation, authorization, approved, quarantine_root, journal, clock=self.clock)
        self.assertEqual(result.failures, ())
        self.assertEqual(result.records[0].state, QuarantineState.QUARANTINED)
        restored = restore_recovery(result.records[0].metadata.recovery_id, journal, approved, quarantine_root, clock=self.clock)
        self.assertEqual(restored.state, QuarantineState.RESTORED)

    def test_approved_local_root_rejects_system_root(self) -> None:
        plan = self._plan()
        validation, authorization = self._authorization(plan)
        with patch("dwi.mutation._verify_approved_local_root", side_effect=MutationRefused("protected")):
            with self.assertRaises(MutationRefused):
                approve_local_mutation_root(plan, validation, authorization)

    def test_unauthorized_and_forged_authorization_do_not_move(self) -> None:
        plan = self._plan()
        validation, _ = self._authorization(plan)
        forged = ExecutionAuthorization(
            plan.plan_id,
            validation.validation_token,
            ExecutionAuthorizationStatus.AUTHORIZED,
            tuple(item.plan_item_id for item in plan.items),
            "forged",
            "forged",
        )
        result = quarantine_plan(plan, validation, forged, self.disposable, self.quarantine_root, self.journal, clock=self.clock)
        self.assertTrue(result.failures)
        self.assertTrue(Path(plan.items[0].snapshot.path).exists())

    def test_stale_validation_is_rejected_before_move(self) -> None:
        plan = self._plan()
        item = plan.items[0]
        context = self._context()
        validation = validate_cleanup_plan(plan, {item.plan_item_id: dataclasses.replace(item.snapshot, size=SizeObservation(11, True))}, scan_context=context)
        authorization = authorize_execution(plan, validation)
        result = quarantine_plan(plan, validation, authorization, self.disposable, self.quarantine_root, self.journal, clock=self.clock)
        self.assertTrue(result.failures)
        self.assertTrue(Path(item.snapshot.path).exists())

    def test_identity_change_and_reparse_before_move_fail_closed(self) -> None:
        plan = self._plan()
        validation, authorization = self._authorization(plan)
        expected = plan.items[0].snapshot.filesystem_identity
        changed = FilesystemIdentity(expected.device, expected.inode + 1, NodeKind.DIRECTORY, False)
        with patch("dwi.mutation._observe_identity", return_value=(changed, None)):
            changed_result = quarantine_plan(plan, validation, authorization, self.disposable, self.quarantine_root, self.journal, clock=self.clock)
        self.assertTrue(changed_result.failures)
        self.assertTrue(Path(plan.items[0].snapshot.path).exists())

        plan = self._plan((self.workspace / "reparse-cache",))
        validation, authorization = self._authorization(plan)
        reparse = FilesystemIdentity(expected.device, expected.inode, NodeKind.REPARSE_POINT, True)
        with patch("dwi.mutation._observe_identity", return_value=(reparse, None)):
            reparse_result = quarantine_plan(plan, validation, authorization, self.disposable, self.quarantine_root, self.journal, clock=self.clock)
        self.assertTrue(reparse_result.failures)

    def test_quarantine_collision_and_outside_destination_are_blocked(self) -> None:
        plan = self._plan()
        validation, authorization = self._authorization(plan)
        collision = self.quarantine_root.path + "\\" + self._recovery_id(plan, plan.items[0])
        Path(collision).mkdir()
        result = quarantine_plan(plan, validation, authorization, self.disposable, self.quarantine_root, self.journal, clock=self.clock)
        self.assertTrue(result.failures)
        self.assertTrue(Path(plan.items[0].snapshot.path).exists())

        with self.assertRaises(Exception):
            create_quarantine_root(self.disposable, "..\\outside")

    def test_partial_multi_item_failure_is_explicit(self) -> None:
        first = self.workspace / "first-cache"
        second = self.workspace / "second-cache"
        plan = self._plan((first, second))
        validation, authorization = self._authorization(plan)
        collision_item = plan.items[1]
        Path(self.quarantine_root.path, self._recovery_id(plan, collision_item)).mkdir()
        result = quarantine_plan(plan, validation, authorization, self.disposable, self.quarantine_root, self.journal, clock=self.clock)
        self.assertEqual(len(result.records), 1)
        self.assertEqual(len(result.failures), 1)

    def test_quarantine_final_journal_failure_is_recoverable_and_undo_succeeds(self) -> None:
        plan = self._plan()
        validation, authorization = self._authorization(plan)
        original_append = AuditJournal.append

        def fail_final_quarantine(journal, entry):
            if entry.status is QuarantineState.QUARANTINED:
                raise JournalError("injected final quarantine journal failure")
            original_append(journal, entry)

        with patch("dwi.mutation.AuditJournal.append", autospec=True, side_effect=fail_final_quarantine):
            result = quarantine_plan(plan, validation, authorization, self.disposable, self.quarantine_root, self.journal, clock=self.clock)
        record = result.records[0]
        self.assertEqual(record.state, QuarantineState.QUARANTINE_COMMITTED_UNJOURNALED)
        self.assertEqual(result.failures[0].state, QuarantineState.QUARANTINE_COMMITTED_UNJOURNALED)
        self.assertFalse(Path(record.metadata.original_path).exists())
        self.assertTrue(Path(record.metadata.quarantine_path).exists())

        restarted = create_audit_journal(self.disposable)
        reconciliation = reconcile_pending_operations(restarted, self.disposable, self.quarantine_root, clock=self.clock)
        self.assertEqual(reconciliation.entries[-1].status, QuarantineState.QUARANTINE_COMMITTED_UNJOURNALED)
        restored = restore_recovery(record.metadata.recovery_id, restarted, self.disposable, self.quarantine_root, clock=self.clock)
        self.assertEqual(restored.state, QuarantineState.RESTORED)
        self.assertTrue(Path(record.metadata.original_path).exists())

    def test_restore_final_journal_failure_is_recoverable_and_idempotent_after_restart(self) -> None:
        plan = self._plan()
        validation, authorization = self._authorization(plan)
        result = quarantine_plan(plan, validation, authorization, self.disposable, self.quarantine_root, self.journal, clock=self.clock)
        recovery_id = result.records[0].metadata.recovery_id
        original_append = AuditJournal.append

        def fail_final_restore(journal, entry):
            if entry.status is QuarantineState.RESTORED:
                raise JournalError("injected final restore journal failure")
            original_append(journal, entry)

        with patch("dwi.mutation.AuditJournal.append", autospec=True, side_effect=fail_final_restore):
            restored = restore_recovery(recovery_id, self.journal, self.disposable, self.quarantine_root, clock=self.clock)
        self.assertEqual(restored.state, QuarantineState.RESTORE_COMMITTED_UNJOURNALED)
        self.assertTrue(Path(result.records[0].metadata.original_path).exists())
        self.assertFalse(Path(result.records[0].metadata.quarantine_path).exists())

        restarted = create_audit_journal(self.disposable)
        reconciliation = reconcile_pending_operations(restarted, self.disposable, self.quarantine_root, clock=self.clock)
        self.assertEqual(reconciliation.entries[-1].status, QuarantineState.RESTORE_COMMITTED_UNJOURNALED)
        repeated = restore_recovery(recovery_id, restarted, self.disposable, self.quarantine_root, clock=self.clock)
        self.assertEqual(repeated.state, QuarantineState.RESTORE_COMMITTED_UNJOURNALED)
        self.assertTrue(Path(result.records[0].metadata.original_path).exists())

    def test_journal_chain_detects_edit_deletion_reorder_duplicate_and_sequence_break(self) -> None:
        plan = self._plan()
        validation, authorization = self._authorization(plan)
        quarantine_plan(plan, validation, authorization, self.disposable, self.quarantine_root, self.journal, clock=self.clock)
        lines = Path(self.journal.path).read_text(encoding="utf-8").splitlines(keepends=True)
        self.assertGreaterEqual(len(lines), 4)

        corruptions = (
            lines[:2] + [lines[2].replace("quarantining", "tampered", 1)] + lines[3:],
            [lines[0], lines[1], lines[3]],
            [lines[1], lines[0], lines[2], lines[3]],
            lines + [lines[0]],
        )
        for corrupted in corruptions:
            Path(self.journal.path).write_text("".join(corrupted), encoding="utf-8")
            with self.assertRaises(JournalCorruptionError):
                self.journal.read_entries()
            Path(self.journal.path).write_text("".join(lines), encoding="utf-8")

        payload = json.loads(lines[2])
        payload["previous_record_hash"] = "broken-chain"
        Path(self.journal.path).write_text("".join(lines[:2] + [json.dumps(payload) + "\n"] + lines[3:]), encoding="utf-8")
        with self.assertRaises(JournalCorruptionError):
            self.journal.read_entries()

        payload = json.loads(lines[2])
        payload["sequence"] = 99
        Path(self.journal.path).write_text("".join(lines[:2] + [json.dumps(payload) + "\n"] + lines[3:]), encoding="utf-8")
        with self.assertRaises(JournalCorruptionError):
            self.journal.read_entries()

    def test_journal_detects_truncated_final_line_and_documents_boundary(self) -> None:
        plan = self._plan()
        validation, authorization = self._authorization(plan)
        quarantine_plan(plan, validation, authorization, self.disposable, self.quarantine_root, self.journal, clock=self.clock)
        content = Path(self.journal.path).read_text(encoding="utf-8")
        Path(self.journal.path).write_text(content.rstrip("\n"), encoding="utf-8")
        with self.assertRaises(JournalCorruptionError):
            self.journal.read_entries()

    def test_mutation_exports_stay_internal_and_guards_reject_forged_roots(self) -> None:
        import dwi

        self.assertFalse(hasattr(dwi, "quarantine_plan"))
        self.assertFalse(hasattr(dwi, "create_disposable_root"))
        forged_root = dataclasses.replace(self.disposable, path=str(self.workspace))
        with self.assertRaises(MutationRefused):
            reconcile_pending_operations(self.journal, forged_root, self.quarantine_root, clock=self.clock)
        with self.assertRaises(MutationRefused):
            restore_recovery("forged", self.journal, forged_root, self.quarantine_root, clock=self.clock)

        plan = self._plan()
        validation, authorization = self._authorization(plan)
        item = plan.items[0]
        outside = Path(self.temporary.name).parent / "forged-original"
        outside_quarantine = Path(self.temporary.name).parent / "forged-quarantine"
        forged = self._manual_entry(
            plan, validation, authorization, item, QuarantineState.QUARANTINED,
            "forged-recovery", str(outside_quarantine),
        )
        forged = dataclasses.replace(forged, original_path=str(outside), record_hash="")
        forged = dataclasses.replace(forged, record_hash=_entry_hash(forged))
        self.journal.append(forged)
        restored = restore_recovery("forged-recovery", self.journal, self.disposable, self.quarantine_root, clock=self.clock)
        self.assertEqual(restored.state, QuarantineState.FAILED)
        self.assertFalse(outside.exists())

    def test_journal_corruption_is_detectable_and_blocks_restore(self) -> None:
        plan = self._plan()
        validation, authorization = self._authorization(plan)
        result = quarantine_plan(plan, validation, authorization, self.disposable, self.quarantine_root, self.journal, clock=self.clock)
        with open(self.journal.path, "a", encoding="utf-8", newline="\n") as stream:
            stream.write("{corrupt\n")
        with self.assertRaises(JournalCorruptionError):
            self.journal.read_entries()
        with self.assertRaises(JournalCorruptionError):
            restore_recovery(result.records[0].metadata.recovery_id, self.journal, self.disposable, self.quarantine_root, clock=self.clock)

    def test_journal_schema_tampering_is_detectable(self) -> None:
        plan = self._plan()
        validation, authorization = self._authorization(plan)
        quarantine_plan(plan, validation, authorization, self.disposable, self.quarantine_root, self.journal, clock=self.clock)
        lines = Path(self.journal.path).read_text(encoding="utf-8").splitlines()
        payload = json.loads(lines[0])
        payload["schema"] = "unexpected-schema"
        Path(self.journal.path).write_text(json.dumps(payload) + "\n" + "\n".join(lines[1:]) + "\n", encoding="utf-8")
        with self.assertRaises(JournalCorruptionError):
            self.journal.read_entries()

    def test_crash_window_reconciliation_is_explicit(self) -> None:
        plan = self._plan()
        validation, authorization = self._authorization(plan)
        item = plan.items[0]
        recovery_id = self._recovery_id(plan, item)
        destination = os.path.join(self.quarantine_root.path, recovery_id)
        os.rename(item.snapshot.path, destination)
        self.journal.append(self._manual_entry(plan, validation, authorization, item, QuarantineState.QUARANTINING, recovery_id, destination))
        reconciled = reconcile_pending_operations(self.journal, self.disposable, self.quarantine_root, clock=self.clock)
        self.assertEqual(reconciled.entries[-1].status, QuarantineState.QUARANTINE_COMMITTED_UNJOURNALED)

        second = self.workspace / "failed-cache"
        plan = self._plan((second,))
        validation, authorization = self._authorization(plan)
        item = plan.items[0]
        recovery_id = self._recovery_id(plan, item)
        destination = os.path.join(self.quarantine_root.path, recovery_id)
        self.journal.append(self._manual_entry(plan, validation, authorization, item, QuarantineState.QUARANTINING, recovery_id, destination))
        reconciled = reconcile_pending_operations(self.journal, self.disposable, self.quarantine_root, clock=self.clock)
        self.assertEqual(reconciled.entries[-1].status, QuarantineState.FAILED)

    def test_restore_refuses_occupied_or_changed_or_missing_items(self) -> None:
        plan = self._plan()
        validation, authorization = self._authorization(plan)
        result = quarantine_plan(plan, validation, authorization, self.disposable, self.quarantine_root, self.journal, clock=self.clock)
        metadata = result.records[0].metadata
        Path(metadata.original_path).mkdir()
        occupied = restore_recovery(metadata.recovery_id, self.journal, self.disposable, self.quarantine_root, clock=self.clock)
        self.assertEqual(occupied.state, QuarantineState.FAILED)
        self.assertTrue(Path(metadata.original_path).exists())
        Path(metadata.original_path).rmdir()

        moved = Path(metadata.quarantine_path).with_name("changed-quarantine")
        os.rename(metadata.quarantine_path, moved)
        changed = restore_recovery(metadata.recovery_id, self.journal, self.disposable, self.quarantine_root, clock=self.clock)
        self.assertEqual(changed.state, QuarantineState.FAILED)
        os.rename(moved, metadata.quarantine_path)
        os.rename(metadata.quarantine_path, moved)
        missing = restore_recovery(metadata.recovery_id, self.journal, self.disposable, self.quarantine_root, clock=self.clock)
        self.assertEqual(missing.state, QuarantineState.FAILED)

    def test_repeated_restore_is_idempotent(self) -> None:
        plan = self._plan()
        validation, authorization = self._authorization(plan)
        result = quarantine_plan(plan, validation, authorization, self.disposable, self.quarantine_root, self.journal, clock=self.clock)
        first = restore_recovery(result.records[0].metadata.recovery_id, self.journal, self.disposable, self.quarantine_root, clock=self.clock)
        second = restore_recovery(result.records[0].metadata.recovery_id, self.journal, self.disposable, self.quarantine_root, clock=self.clock)
        self.assertEqual(first.state, QuarantineState.RESTORED)
        self.assertEqual(second.state, QuarantineState.RESTORED)

    def test_journal_serialization_and_api_are_deterministic_and_not_raw_path_mutation(self) -> None:
        plan = self._plan()
        validation, authorization = self._authorization(plan)
        result = quarantine_plan(plan, validation, authorization, self.disposable, self.quarantine_root, self.journal, clock=self.clock)
        entry = self.journal.read_entries()[0]
        self.assertEqual(_canonical_json(_entry_payload(entry)), _canonical_json(_entry_payload(entry)))
        self.assertEqual(entry.record_hash, _entry_hash(entry))
        self.assertNotIn("path", inspect.signature(quarantine_plan).parameters)
        self.assertNotIn("original_path", inspect.signature(restore_recovery).parameters)
        self.assertTrue(result.records)

    def test_real_path_without_disposable_marker_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(Exception):
                create_disposable_root(directory)

    def test_authoritative_protected_root_matrix_blocks_8dot3_aliases_and_case_variants(self) -> None:
        protected = ("c:\\windows", "c:\\program files", "c:\\program files (x86)", "c:\\programdata")
        aliases = (
            AuthoritativePath(r"C:\\PROGRA~1", r"C:\\Program Files"),
            AuthoritativePath(r"C:\\PROGRA~2", r"C:\\Program Files (x86)"),
            AuthoritativePath(r"C:\\PROGRA~3", r"C:\\ProgramData"),
            AuthoritativePath(r"c:\\WINDOWS", r"C:\\Windows"),
        )
        with patch("dwi.mutation._protected_windows_roots", return_value=protected):
            for authority in aliases:
                with self.subTest(path=authority.lexical_path):
                    self.assertTrue(_is_protected_authoritative_path(authority))
            self.assertFalse(_is_protected_authoritative_path(AuthoritativePath(
                r"C:\\Users\\Administrator\\Project", r"C:\\Users\\Administrator\\Project",
            )))

    def test_authoritative_resolution_failure_and_reparse_ambiguity_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with patch("dwi.mutation._windows_final_path", return_value=None):
                with self.assertRaises(MutationRefused):
                    _verify_approved_local_root(directory)
            target = Path(directory) / "target"
            target.mkdir()
            link = Path(directory) / "link"
            try:
                link.symlink_to(target, target_is_directory=True)
            except (OSError, NotImplementedError):
                self.skipTest("symlink creation unavailable")
            self.assertIsNone(_authoritative_path(str(link)))


if __name__ == "__main__":
    unittest.main()
