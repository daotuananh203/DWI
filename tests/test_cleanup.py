import dataclasses
import unittest

from dwi import (
    ActionEligibility,
    ActivityState,
    ApprovedRoot,
    ArtifactKind,
    CandidateEligibility,
    CandidateSelection,
    CleanupCandidate,
    Evidence,
    EvidenceBundle,
    EvidencePolarity,
    EvidenceRequirement,
    Confidence,
    ExecutionAuthorization,
    ExecutionAuthorizationStatus,
    FilesystemIdentity,
    Finding,
    MutationIntent,
    NodeKind,
    ObservationStatus,
    ObservedNode,
    PlanValidation,
    PlanValidationStatus,
    ProtectionClass,
    Provenance,
    PytestCacheInterpretation,
    ReachabilityState,
    RegenerabilityState,
    RegenerationCost,
    RiskLabel,
    ScanCompleteness,
    SizeObservation,
    TrustedScanContext,
    ValidationFailure,
    authorize_execution,
    authorization_to_json,
    create_cleanup_plan,
    evaluate_safety,
    plan_to_json,
    scan_context_from_system_scan,
    scan_completeness_from_system_scan,
    validate_cleanup_plan,
    validation_to_json,
)
from dwi.policy import SafetyContext
from dwi.scan_control import ScanTermination
from dwi.system_scan import RootObservation, RootScope, RootStatus, SystemScan
from dwi.system_scan import RootBoundary


class CleanupContractTests(unittest.TestCase):
    def _context(
        self,
        root: str = "C:\\workspace",
        status: RootStatus = RootStatus.COMPLETE,
        failures: tuple[str, ...] = (),
    ) -> TrustedScanContext:
        scan = SystemScan(
            requested_roots=(root,),
            root_observations=(RootObservation(
                root,
                RootScope.ADDITIONAL_LOCAL,
                "root",
                RootBoundary.LOCAL_DIRECTORY,
                status,
                "synthetic",
            ),),
            workspace_findings=(),
            global_storage_findings=(),
            git_observations=(),
            observation_failures=failures,
            ambiguous_boundaries=(),
            termination=ScanTermination.COMPLETED,
            nodes_observed=1,
            files_observed=0,
        )
        return scan_context_from_system_scan(scan)

    def _finding(self, path: str = "C:\\workspace\\.pytest_cache") -> Finding:
        evidence = Evidence(
            key="provenance",
            source="synthetic-cleanup-fixture",
            description="Synthetic high-confidence provenance evidence.",
            observation_status=ObservationStatus.OBSERVED,
            polarity=EvidencePolarity.SUPPORTS,
            confidence=Confidence.HIGH,
            value="pytest",
        )
        bundle = EvidenceBundle((evidence,), (EvidenceRequirement("provenance", Confidence.HIGH),))
        node = ObservedNode(path, NodeKind.DIRECTORY, ProtectionClass.ORDINARY)
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
        return Finding(ArtifactKind.PYTEST_CACHE, path, bundle, interpretation, selection, decision, SizeObservation(10, True))

    def _identity(self, inode: int = 10) -> FilesystemIdentity:
        return FilesystemIdentity(1, inode, NodeKind.DIRECTORY, False)

    def _plan(self, finding: Finding | None = None, context: TrustedScanContext | None = None):
        finding = finding or self._finding()
        context = context or self._context()
        return create_cleanup_plan(
            (finding,),
            filesystem_identities={finding.path: self._identity()},
            scan_context=context,
            approved_root=context.approved_roots[0],
        )

    def test_plan_is_immutable_and_deterministic(self) -> None:
        first = self._plan()
        second = self._plan()
        self.assertEqual(first, second)
        self.assertEqual(plan_to_json(first), plan_to_json(second))
        with self.assertRaises(dataclasses.FrozenInstanceError):
            first.plan_id = first.plan_id  # type: ignore[misc]

    def test_arbitrary_raw_path_list_cannot_become_plan(self) -> None:
        with self.assertRaises(TypeError):
            create_cleanup_plan(["C:\\arbitrary\\path"], filesystem_identities={}, scan_context=self._context(), approved_root=self._context().approved_roots[0])  # type: ignore[arg-type]

    def test_review_never_delete_and_blocked_findings_are_excluded(self) -> None:
        base = self._finding()
        review_decision = dataclasses.replace(base.safety_decision, risk_label=RiskLabel.REVIEW_REQUIRED, action_eligibility=ActionEligibility.REQUIRES_REVIEW)
        never_decision = dataclasses.replace(base.safety_decision, risk_label=RiskLabel.NEVER_DELETE, action_eligibility=ActionEligibility.BLOCKED)
        blocked_decision = dataclasses.replace(base.safety_decision, action_eligibility=ActionEligibility.BLOCKED)
        findings = (
            dataclasses.replace(base, safety_decision=review_decision, path="C:\\review"),
            dataclasses.replace(base, safety_decision=never_decision, path="C:\\protected"),
            dataclasses.replace(base, safety_decision=blocked_decision, path="C:\\active"),
        )
        context = self._context()
        plan = create_cleanup_plan(
            findings,
            filesystem_identities={path: self._identity() for path in ["C:\\review", "C:\\protected", "C:\\active"]},
            scan_context=context,
            approved_root=context.approved_roots[0],
        )
        self.assertFalse(plan.items)
        self.assertEqual(len(plan.exclusions), 3)

    def test_plan_creation_does_not_authorize_execution(self) -> None:
        plan = self._plan()
        self.assertFalse(authorize_execution(plan, validate_cleanup_plan(plan, {}, scan_context=self._context())).is_authorized)

    def test_omitted_scan_context_cannot_default_to_complete(self) -> None:
        context = self._context()
        finding = self._finding()
        with self.assertRaises(TypeError):
            create_cleanup_plan(  # type: ignore[call-overload]
                (finding,),
                filesystem_identities={finding.path: self._identity()},
                approved_root=context.approved_roots[0],
            )
        plan = self._plan()
        with self.assertRaises(TypeError):
            validate_cleanup_plan(plan, {plan.items[0].plan_item_id: plan.items[0].snapshot})  # type: ignore[call-overload]

    def test_invalid_filesystem_identity_never_becomes_plannable(self) -> None:
        self.assertFalse(FilesystemIdentity(None, None, NodeKind.DIRECTORY, False).is_suitable_for_planning)
        for device, inode in ((0, 10), (10, 0), (-1, 10), (10, -1)):
            with self.subTest(device=device, inode=inode):
                with self.assertRaises(ValueError):
                    FilesystemIdentity(device, inode, NodeKind.DIRECTORY, False)
        finding = self._finding()
        context = self._context()
        plan = create_cleanup_plan(
            (finding,),
            filesystem_identities={finding.path: FilesystemIdentity(None, None, NodeKind.DIRECTORY, False)},
            scan_context=context,
            approved_root=context.approved_roots[0],
        )
        self.assertFalse(plan.items)

    def test_plan_requires_absolute_path_and_bound_root(self) -> None:
        context = self._context()
        for path in (
            "relative\\.pytest_cache",
            "C:\\workspace\\..\\outside\\.pytest_cache",
            "C:\\other\\.pytest_cache",
        ):
            with self.subTest(path=path):
                finding = self._finding(path)
                plan = create_cleanup_plan(
                    (finding,),
                    filesystem_identities={path: self._identity()},
                    scan_context=context,
                    approved_root=context.approved_roots[0],
                )
                self.assertFalse(plan.items)
        equivalent = self._finding("c:\\WORKSPACE\\.pytest_cache")
        plan = create_cleanup_plan(
            (equivalent,),
            filesystem_identities={equivalent.path: self._identity()},
            scan_context=context,
            approved_root=context.approved_roots[0],
        )
        self.assertEqual(plan.items[0].snapshot.path, "c:\\workspace\\.pytest_cache")
        foreign_context = self._context("C:\\other")
        with self.assertRaises(ValueError):
            create_cleanup_plan(
                (self._finding(),),
                filesystem_identities={self._finding().path: self._identity()},
                scan_context=context,
                approved_root=foreign_context.approved_roots[0],
            )
        reparse_plan = create_cleanup_plan(
            (self._finding(),),
            filesystem_identities={self._finding().path: FilesystemIdentity(1, 10, NodeKind.DIRECTORY, True)},
            scan_context=context,
            approved_root=context.approved_roots[0],
        )
        self.assertFalse(reparse_plan.items)

    def test_only_engine_validation_can_authorize_exact_plan_and_state(self) -> None:
        plan = self._plan()
        item = plan.items[0]
        current = {item.plan_item_id: item.snapshot}
        context = self._context()
        legitimate = validate_cleanup_plan(plan, current, scan_context=context)
        self.assertEqual(legitimate.status, PlanValidationStatus.VALID)
        authorization = authorize_execution(plan, legitimate)
        self.assertTrue(authorization.is_authorized)
        fabricated_authorization = ExecutionAuthorization(
            plan.plan_id,
            legitimate.validation_token,
            ExecutionAuthorizationStatus.AUTHORIZED,
            (item.plan_item_id,),
            "fabricated",
            "fabricated",
        )
        self.assertFalse(fabricated_authorization.is_authorized)

        forged = PlanValidation(plan.plan_id, PlanValidationStatus.VALID, (), legitimate.validation_token)
        self.assertFalse(authorize_execution(plan, forged).is_authorized)
        self.assertFalse(authorization.matches_validation(forged))
        copied_token = dataclasses.replace(legitimate, validation_token="copied-token")
        self.assertFalse(authorize_execution(plan, copied_token).is_authorized)
        self.assertFalse(authorization.matches_validation(copied_token))
        modified = dataclasses.replace(
            legitimate,
            status=PlanValidationStatus.BLOCKED,
            failures=(ValidationFailure("forged", "modified validation"),),
        )
        self.assertFalse(authorize_execution(plan, modified).is_authorized)
        stale = validate_cleanup_plan(
            plan,
            {item.plan_item_id: dataclasses.replace(item.snapshot, size=SizeObservation(11, True))},
            scan_context=context,
        )
        self.assertFalse(authorize_execution(plan, stale).is_authorized)
        other_plan = self._plan(self._finding("C:\\workspace\\other\\.pytest_cache"))
        self.assertFalse(authorize_execution(other_plan, legitimate).is_authorized)

    def test_validation_and_authorization_serialization_is_deterministic(self) -> None:
        plan = self._plan()
        item = plan.items[0]
        validation = validate_cleanup_plan(
            plan,
            {item.plan_item_id: item.snapshot},
            scan_context=self._context(),
        )
        authorization = authorize_execution(plan, validation)
        self.assertEqual(validation_to_json(validation), validation_to_json(validation))
        self.assertEqual(authorization_to_json(authorization), authorization_to_json(authorization))
        self.assertNotIn("proof", validation_to_json(validation))

    def test_changed_filesystem_identity_invalidates_validation(self) -> None:
        plan = self._plan()
        item = plan.items[0]
        current = dataclasses.replace(item.snapshot, filesystem_identity=self._identity(99))
        validation = validate_cleanup_plan(plan, {item.plan_item_id: current}, scan_context=self._context())
        self.assertEqual(validation.status.value, "stale_changed")
        self.assertFalse(authorize_execution(plan, validation).is_authorized)

    def test_changed_risk_label_blocks_validation(self) -> None:
        plan = self._plan()
        item = plan.items[0]
        current = dataclasses.replace(item.snapshot, risk_label=RiskLabel.REVIEW_REQUIRED, action_eligibility=ActionEligibility.REQUIRES_REVIEW)
        validation = validate_cleanup_plan(plan, {item.plan_item_id: current}, scan_context=self._context())
        self.assertEqual(validation.status.value, "blocked")
        self.assertIn("risk-veto", [failure.code for failure in validation.failures])

    def test_protection_reference_and_activity_vetoes_block(self) -> None:
        plan = self._plan()
        item = plan.items[0]
        for field, value, code in (
            ("protection", ProtectionClass.PROTECTED, "protection-veto"),
            ("reachability", ReachabilityState.CONFIRMED_REFERENCED, "reachability-veto"),
            ("activity", ActivityState.ACTIVE_RUNTIME, "activity-veto"),
        ):
            with self.subTest(field=field):
                current = dataclasses.replace(item.snapshot, **{field: value})
                validation = validate_cleanup_plan(plan, {item.plan_item_id: current}, scan_context=self._context())
                self.assertEqual(validation.status.value, "blocked")
                self.assertIn(code, [failure.code for failure in validation.failures])

    def test_valid_authorization_cannot_match_new_validation_state(self) -> None:
        plan = self._plan()
        item = plan.items[0]
        current = {item.plan_item_id: item.snapshot}
        validation = validate_cleanup_plan(plan, current, scan_context=self._context())
        authorization = authorize_execution(plan, validation)
        self.assertEqual(authorization.status, ExecutionAuthorizationStatus.AUTHORIZED)
        changed = dataclasses.replace(item.snapshot, size=SizeObservation(11, True))
        new_validation = validate_cleanup_plan(plan, {item.plan_item_id: changed}, scan_context=self._context())
        self.assertFalse(authorization.matches_validation(new_validation))

    def test_partial_or_failed_scan_cannot_satisfy_plan_or_validation(self) -> None:
        finding = self._finding()
        for completeness in (ScanCompleteness.PARTIAL, ScanCompleteness.FAILED):
            with self.subTest(completeness=completeness):
                context = self._context(status=RootStatus.PARTIAL if completeness is ScanCompleteness.PARTIAL else RootStatus.FAILED)
                plan = create_cleanup_plan(
                    (finding,),
                    filesystem_identities={finding.path: self._identity()},
                    scan_context=context,
                    approved_root=context.approved_roots[0],
                )
                self.assertFalse(plan.items)
                self.assertFalse(authorize_execution(plan, validate_cleanup_plan(plan, {}, scan_context=context)).is_authorized)

    def test_system_scan_completeness_maps_partial_root_conservatively(self) -> None:
        scan = SystemScan(
            requested_roots=("C:\\workspace",),
            root_observations=(RootObservation("C:\\workspace", RootScope.ADDITIONAL_LOCAL, "root", RootBoundary.LOCAL_DIRECTORY, RootStatus.PARTIAL, "incomplete"),),
            workspace_findings=(),
            global_storage_findings=(),
            git_observations=(),
            observation_failures=(),
            ambiguous_boundaries=(),
            termination=ScanTermination.COMPLETED,
            nodes_observed=1,
            files_observed=0,
        )
        self.assertEqual(scan_completeness_from_system_scan(scan), ScanCompleteness.PARTIAL)

    def test_global_failure_evidence_cannot_become_complete_context(self) -> None:
        context = self._context(failures=("global evidence failed",))
        self.assertEqual(context.completeness, ScanCompleteness.PARTIAL)
        finding = self._finding()
        plan = create_cleanup_plan(
            (finding,),
            filesystem_identities={finding.path: self._identity()},
            scan_context=context,
            approved_root=context.approved_roots[0],
        )
        self.assertFalse(plan.items)

    def test_revalidation_rejects_current_context_for_wrong_root(self) -> None:
        plan = self._plan()
        item = plan.items[0]
        validation = validate_cleanup_plan(
            plan,
            {item.plan_item_id: item.snapshot},
            scan_context=self._context("C:\\other"),
        )
        self.assertEqual(validation.status, PlanValidationStatus.BLOCKED)
        self.assertFalse(authorize_execution(plan, validation).is_authorized)

    def test_recovery_contract_is_serializable_without_implementing_mutation(self) -> None:
        plan = self._plan()
        item = plan.items[0]
        from dwi import QuarantineRecord, QuarantineState, RecoveryMetadata

        record = QuarantineRecord(RecoveryMetadata("recovery-1", item.snapshot.path, None, plan.plan_id, item.plan_item_id, "2026-01-01T00:00:00Z"), QuarantineState.PLANNED)
        self.assertEqual(record.state, QuarantineState.PLANNED)


if __name__ == "__main__":
    unittest.main()
