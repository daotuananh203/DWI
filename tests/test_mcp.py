from __future__ import annotations

import io
import json
import gc
import threading
import unittest
import weakref
from types import SimpleNamespace
from unittest.mock import patch

from dwi.application import CleanupApplicationResult, CleanupItemOutcome, CleanupItemResult, CleanupSessionState
from dwi.cleanup import FilesystemIdentity, QuarantineState
from dwi.contracts import ArtifactKind
from dwi.domain import (
    ActionEligibility,
    ActivityState,
    CleanupCandidate,
    Confidence,
    Evidence,
    EvidenceBundle,
    EvidencePolarity,
    EvidenceRequirement,
    NodeKind,
    ObservedNode,
    ObservationStatus,
    ProtectionClass,
    Provenance,
    ReachabilityState,
    ReclaimPriority,
    RegenerabilityState,
    RegenerationCost,
)
from dwi.mcp import McpServer, McpService, run_mcp_smoke
from dwi.mcp.models import McpErrorCode, McpHandleState, McpHandleType, McpServiceError
from dwi.mcp.state_store import OpaqueHandleStore
from dwi.mutation import RestoreResult
from dwi.pipeline import CandidateEligibility, CandidateSelection, Finding
from dwi.policy import SafetyContext, evaluate_safety
from dwi.pytest_cache import PytestCacheInterpretation
from dwi.scan_control import ScanTermination
from dwi.size import SizeObservation
from dwi.system_scan import RootBoundary, RootObservation, RootScope, RootStatus, SystemScan


ROOT = "C:\\mcp-fixture"
CANDIDATE = ROOT + "\\.pytest_cache"


def _finding(path: str = CANDIDATE) -> Finding:
    evidence = EvidenceBundle(
        observations=(
            Evidence(
                "provenance",
                "mcp-test",
                "High-confidence pytest provenance.",
                ObservationStatus.OBSERVED,
                EvidencePolarity.SUPPORTS,
                Confidence.HIGH,
                "pytest",
            ),
            Evidence(
                "reference_check_observation",
                "mcp-test",
                "No references were confirmed.",
                ObservationStatus.CONFIRMED_ABSENT,
                EvidencePolarity.CONTRADICTS,
                Confidence.HIGH,
                "none",
            ),
        ),
        requirements=(
            EvidenceRequirement("provenance", Confidence.HIGH),
            EvidenceRequirement("reference_check_observation", Confidence.HIGH),
        ),
    )
    candidate = CleanupCandidate(
        ObservedNode(path, NodeKind.DIRECTORY, ProtectionClass.ORDINARY),
        evidence,
    )
    selection = CandidateSelection(CandidateEligibility.SELECTED, evidence, candidate)
    interpretation = PytestCacheInterpretation(
        Provenance("python", "pytest", Confidence.HIGH, ("provenance",)),
        RegenerabilityState.REPRODUCIBLE,
        RegenerationCost.LOW,
        ReachabilityState.CONFIRMED_UNREFERENCED,
        ActivityState.INACTIVE,
        ProtectionClass.ORDINARY,
        ReclaimPriority.HIGH,
    )
    decision = evaluate_safety(SafetyContext(
        candidate=candidate,
        evidence=evidence,
        provenance=interpretation.provenance,
        regenerability=interpretation.regenerability,
        regeneration_cost=interpretation.regeneration_cost,
        reachability=interpretation.reachability,
        activity=interpretation.activity,
        protection=interpretation.protection,
        reclaim_priority=interpretation.reclaim_priority,
    ))
    return Finding(
        ArtifactKind.PYTEST_CACHE,
        path,
        evidence,
        interpretation,
        selection,
        decision,
        SizeObservation(8, True),
    )


def _scan(finding: Finding | None = None) -> SystemScan:
    return SystemScan(
        requested_roots=(ROOT,),
        root_observations=(RootObservation(
            ROOT,
            RootScope.ADDITIONAL_LOCAL,
            "mcp-fixture",
            RootBoundary.LOCAL_DIRECTORY,
            RootStatus.COMPLETE,
            "synthetic complete test scan",
        ),),
        workspace_findings=(finding,) if finding is not None else (),
        global_storage_findings=(),
        git_observations=(),
        observation_failures=(),
        ambiguous_boundaries=(),
        termination=ScanTermination.COMPLETED,
        nodes_observed=2,
        files_observed=0,
    )


class McpTestBase(unittest.TestCase):
    def setUp(self) -> None:
        self.finding = _finding()
        self.scan = _scan(self.finding)
        self.identity = FilesystemIdentity(1, 2, NodeKind.DIRECTORY, False, CANDIDATE)
        self.service = McpService(scan_fn=lambda _options: self.scan, handle_ttl_seconds=900)
        self.identity_patch = patch("dwi.cleanup_engine._observe_identity", return_value=(self.identity, None))
        self.identity_patch.start()
        self.addCleanup(self.identity_patch.stop)

    def scan_handle(self) -> str:
        return self.service.call_tool("dwi_scan_root", {"root": ROOT})["scan_handle"]

    def review_handle(self) -> tuple[str, str]:
        scan_result = self.service.call_tool("dwi_scan_root", {"root": ROOT})
        finding_id = self.service.call_tool("dwi_list_findings", {"scan_handle": scan_result["scan_handle"]})["findings"][0]["finding_id"]
        review = self.service.call_tool("dwi_create_cleanup_review", {
            "scan_handle": scan_result["scan_handle"],
            "finding_ids": [finding_id],
        })
        return review["review_handle"], finding_id


class McpBoundaryTests(McpTestBase):
    def test_stdio_initialize_and_tool_discovery_are_local_protocol_only(self) -> None:
        output = io.StringIO()
        server = McpServer(self.service)
        server.serve_stdio(io.StringIO(
            json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}) + "\n"
            + json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}) + "\n"
            + json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}) + "\n"
        ), output)
        responses = [json.loads(line) for line in output.getvalue().splitlines()]
        self.assertEqual(responses[0]["result"]["serverInfo"]["name"], "dwi-mcp")
        names = {tool["name"] for tool in responses[1]["result"]["tools"]}
        self.assertIn("dwi_scan_system", names)
        self.assertIn("dwi_request_undo", names)
        self.assertNotIn("dwi_confirm_cleanup", names)
        self.assertNotIn("delete_file", names)

    def test_forged_wrong_stale_and_cross_session_handles_fail_closed(self) -> None:
        first = self.scan_handle()
        second = self.scan_handle()
        with self.assertRaises(McpServiceError) as context:
            self.service.call_tool("dwi_get_scan_summary", {"scan_handle": "scan_forged"})
        self.assertEqual(context.exception.code, McpErrorCode.INVALID_HANDLE)
        with self.assertRaises(McpServiceError) as context:
            self.service.call_tool("dwi_get_scan_summary", {"scan_handle": second.replace("scan_", "review_", 1)})
        self.assertEqual(context.exception.code, McpErrorCode.INVALID_HANDLE)
        with self.assertRaises(McpServiceError) as context:
            self.service.call_tool("dwi_get_cleanup_review", {"review_handle": first})
        self.assertEqual(context.exception.code, McpErrorCode.WRONG_HANDLE_TYPE)

        now = [0.0]
        expiring = McpService(scan_fn=lambda _options: self.scan, handle_ttl_seconds=1, clock=lambda: now[0])
        with patch("dwi.cleanup_engine._observe_identity", return_value=(self.identity, None)):
            stale = expiring.call_tool("dwi_scan_root", {"root": ROOT})["scan_handle"]
        now[0] = 2.0
        with self.assertRaises(McpServiceError) as context:
            expiring.call_tool("dwi_get_scan_summary", {"scan_handle": stale})
        self.assertEqual(context.exception.code, McpErrorCode.STALE_HANDLE)

    def test_scan_budget_rejects_non_finite_values_before_scan_starts(self) -> None:
        calls: list[object] = []
        service = McpService(scan_fn=lambda options: (calls.append(options), self.scan)[1])
        for value in (float("nan"), float("inf"), float("-inf")):
            with self.subTest(value=value):
                with self.assertRaises(McpServiceError) as context:
                    service.call_tool("dwi_scan_root", {"root": ROOT, "max_seconds": value})
                self.assertEqual(context.exception.code, McpErrorCode.INVALID_REQUEST)
        self.assertEqual(calls, [])

    def test_scan_budget_rejects_invalid_types_and_values(self) -> None:
        calls: list[object] = []
        service = McpService(scan_fn=lambda options: (calls.append(options), self.scan)[1])
        invalid = (
            {"max_seconds": 0},
            {"max_seconds": -1},
            {"max_seconds": 301},
            {"max_nodes": 0},
            {"max_nodes": -1},
            {"max_nodes": 100_001},
            {"max_nodes": 1.5},
            {"max_nodes": True},
            {"max_files": 100_001},
            {"max_files": 1.5},
            {"max_files": False},
        )
        for budget in invalid:
            with self.subTest(budget=budget):
                with self.assertRaises(McpServiceError) as context:
                    service.call_tool("dwi_scan_root", {"root": ROOT, **budget})
                self.assertEqual(context.exception.code, McpErrorCode.INVALID_REQUEST)
        self.assertEqual(calls, [])

    def test_scan_budget_accepts_positive_minimum_normal_and_exact_hard_maximum(self) -> None:
        calls: list[object] = []
        service = McpService(scan_fn=lambda options: (calls.append(options), self.scan)[1])
        for budget in (
            {"max_seconds": 0.000001, "max_nodes": 1, "max_files": 1},
            {"max_seconds": 30.0, "max_nodes": 1000, "max_files": 1000},
            {"max_seconds": 300.0, "max_nodes": 100_000, "max_files": 100_000},
        ):
            with self.subTest(budget=budget):
                result = service.call_tool("dwi_scan_root", {"root": ROOT, **budget})
                self.assertEqual(result["findings_count"], 1)
        self.assertEqual(len(calls), 3)

    def test_selection_is_bound_to_exact_scan_and_raw_safety_fields_are_rejected(self) -> None:
        first = self.service.call_tool("dwi_scan_root", {"root": ROOT})
        second = self.service.call_tool("dwi_scan_root", {"root": ROOT})
        finding_id = self.service.call_tool("dwi_list_findings", {"scan_handle": first["scan_handle"]})["findings"][0]["finding_id"]
        with self.assertRaises(McpServiceError) as context:
            self.service.call_tool("dwi_create_cleanup_review", {
                "scan_handle": second["scan_handle"],
                "finding_ids": [finding_id],
            })
        self.assertEqual(context.exception.code, McpErrorCode.INVALID_HANDLE)
        for extra in ({"path": CANDIDATE}, {"risk_label": "safe"}, {"action_eligibility": "eligible_for_explicit_action"}, {"validation": "valid"}, {"authorization": "authorized"}, {"snapshots": []}):
            with self.subTest(extra=extra):
                with self.assertRaises(McpServiceError) as context:
                    self.service.call_tool("dwi_create_cleanup_review", {
                        "scan_handle": first["scan_handle"],
                        "finding_ids": [finding_id],
                        **extra,
                    })
                self.assertEqual(context.exception.code, McpErrorCode.INVALID_REQUEST)

    def test_read_models_never_serialize_capabilities_or_proofs(self) -> None:
        review_handle, _ = self.review_handle()
        review = self.service.call_tool("dwi_get_cleanup_review", {"review_handle": review_handle})
        encoded = json.dumps(review, sort_keys=True)
        for forbidden in ("_proof", "TrustedSnapshotSet", "ExecutionAuthorization", "validation_token", "authorization_token"):
            self.assertNotIn(forbidden, encoded)
        self.assertIn("risk_label", encoded)
        self.assertIn("rule_trace", encoded)

    def test_agent_cannot_self_confirm_or_bypass_human_channel(self) -> None:
        review_handle, _ = self.review_handle()
        server = McpServer(self.service)
        result = server.handle_message({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "dwi_request_cleanup_execution", "arguments": {"review_handle": review_handle}},
        })
        self.assertEqual(result["result"]["structuredContent"]["error"]["code"], McpErrorCode.HUMAN_CONFIRMATION_REQUIRED.value)
        with self.assertRaises(McpServiceError) as context:
            self.service.confirm_from_human_channel(
                review_handle,
                confirmation_phrase="yes",
                channel=self.service.create_human_channel(),
            )
        self.assertEqual(context.exception.code, McpErrorCode.HUMAN_CONFIRMATION_REQUIRED)
        with self.assertRaises(McpServiceError) as context:
            self.service.call_tool("dwi_confirm_cleanup", {"review_handle": review_handle, "confirmation_phrase": "I reviewed this exact cleanup plan."})
        self.assertEqual(context.exception.code, McpErrorCode.INVALID_REQUEST)
        with self.assertRaises(McpServiceError) as context:
            self.service.call_tool("dwi_request_cleanup_execution", {
                "review_handle": review_handle,
                "confirmation_phrase": "I reviewed this exact cleanup plan.",
            })
        self.assertEqual(context.exception.code, McpErrorCode.INVALID_REQUEST)
        with self.assertRaises(McpServiceError) as context:
            self.service.confirm_from_human_channel(
                review_handle,
                confirmation_phrase="I reviewed this exact cleanup plan.",
                channel=McpService(scan_fn=lambda _options: self.scan).create_human_channel(),
            )
        self.assertEqual(context.exception.code, McpErrorCode.HUMAN_CONFIRMATION_REQUIRED)

        review = self.service.confirm_from_human_channel(
            review_handle,
            confirmation_phrase="I reviewed this exact cleanup plan.",
            channel=self.service.create_human_channel(),
        )
        self.assertEqual(review["status"], McpHandleState.READY_FOR_EXECUTION.value)
        ready = self.service.call_tool("dwi_request_cleanup_execution", {"review_handle": review_handle})
        self.assertEqual(ready["status"], McpHandleState.READY_FOR_EXECUTION.value)


class McpExecutionTests(McpTestBase):
    def _ready_execution(self):
        review_handle, _ = self.review_handle()
        self.service.confirm_from_human_channel(
            review_handle,
            confirmation_phrase="I reviewed this exact cleanup plan.",
            channel=self.service.create_human_channel(),
        )
        return self.service.call_tool("dwi_request_cleanup_execution", {"review_handle": review_handle})["execution_handle"]

    def test_execution_calls_application_service_and_is_one_shot(self) -> None:
        execution_handle = self._ready_execution()
        calls = []
        session = self.service._store.resolve(execution_handle, McpHandleType.EXECUTION).payload.review.session
        fake_result = CleanupApplicationResult(session.session_id, session.plan.plan_id, CleanupSessionState.EXECUTED, None, None, (), None, None)
        with patch("dwi.mcp.service.execute_cleanup_session", side_effect=lambda *args, **kwargs: (calls.append((args, kwargs)), fake_result)[1]), patch.object(self.service, "_runtime_factory", return_value=SimpleNamespace(provider=object())):
            result = self.service.call_tool("dwi_execute_cleanup", {"execution_handle": execution_handle})
        self.assertEqual(result["status"], "EXECUTED")
        self.assertEqual(len(calls), 1)
        self.assertIsNotNone(calls[0][1]["engine_revalidator"])
        with self.assertRaises(McpServiceError) as context:
            self.service.call_tool("dwi_execute_cleanup", {"execution_handle": execution_handle})
        self.assertEqual(context.exception.code, McpErrorCode.CONSUMED_HANDLE)

    def test_concurrent_execution_has_one_winner(self) -> None:
        execution_handle = self._ready_execution()
        session = self.service._store.resolve(execution_handle, McpHandleType.EXECUTION).payload.review.session
        fake_result = CleanupApplicationResult(session.session_id, session.plan.plan_id, CleanupSessionState.EXECUTED, None, None, (), None, None)
        entered = threading.Event()
        release = threading.Event()

        def execute(*_args, **_kwargs):
            entered.set()
            release.wait(2)
            return fake_result

        results: list[object] = []

        def call():
            try:
                results.append(self.service.call_tool("dwi_execute_cleanup", {"execution_handle": execution_handle}))
            except McpServiceError as error:
                results.append(error.code)

        with patch("dwi.mcp.service.execute_cleanup_session", side_effect=execute), patch.object(self.service, "_runtime_factory", return_value=SimpleNamespace(provider=object())):
            first = threading.Thread(target=call)
            second = threading.Thread(target=call)
            first.start()
            self.assertTrue(entered.wait(2))
            second.start()
            second.join(2)
            release.set()
            first.join(2)
        self.assertEqual(len(results), 2)
        self.assertEqual(sum(item == McpErrorCode.CONSUMED_HANDLE for item in results), 1)
        self.assertEqual(sum(isinstance(item, dict) and item["status"] == "EXECUTED" for item in results), 1)

    def test_concurrent_execution_requests_share_one_handle(self) -> None:
        review_handle, _ = self.review_handle()
        self.service.confirm_from_human_channel(
            review_handle,
            confirmation_phrase="I reviewed this exact cleanup plan.",
            channel=self.service.create_human_channel(),
        )
        handles: list[str] = []

        def request() -> None:
            handles.append(self.service.call_tool("dwi_request_cleanup_execution", {"review_handle": review_handle})["execution_handle"])

        threads = [threading.Thread(target=request) for _ in range(3)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(2)
        self.assertEqual(len(set(handles)), 1)

    def test_restart_invalidates_authority_handles(self) -> None:
        handle = self._ready_execution()
        restarted = McpService(scan_fn=lambda _options: self.scan)
        with self.assertRaises(McpServiceError) as context:
            restarted.call_tool("dwi_get_execution_status", {"execution_handle": handle})
        self.assertEqual(context.exception.code, McpErrorCode.INVALID_HANDLE)

    def test_recovery_and_undo_use_server_recovery_handle_only(self) -> None:
        execution_handle = self._ready_execution()
        session = self.service._store.resolve(execution_handle, McpHandleType.EXECUTION).payload.review.session
        recovery_id = "recovery-mcp-fixture"
        entry = SimpleNamespace(
            recovery_id=recovery_id,
            status=QuarantineState.QUARANTINED,
            original_path=CANDIDATE,
            quarantine_path=ROOT + "\\.dwi-quarantine\\payload",
            failure_reason=None,
        )
        fake_runtime = SimpleNamespace(
            provider=object(),
            recovery_entries=lambda: SimpleNamespace(entries=(entry,), failures=()),
            undo=lambda value: RestoreResult(recovery_id, QuarantineState.RESTORED, SimpleNamespace(
                recovery_id=value,
                status=QuarantineState.RESTORED,
                original_path=CANDIDATE,
                quarantine_path=entry.quarantine_path,
                failure_reason=None,
            )),
        )
        fake_result = CleanupApplicationResult(
            session.session_id,
            session.plan.plan_id,
            CleanupSessionState.PARTIAL,
            None,
            None,
            (CleanupItemResult(
                session.plan.items[0].plan_item_id,
                CleanupItemOutcome.RECOVERABLE,
                QuarantineState.QUARANTINED,
                recovery_id,
                None,
            ),),
            None,
            "items were processed independently",
        )
        with patch("dwi.mcp.service.execute_cleanup_session", return_value=fake_result), patch.object(self.service, "_runtime_factory", return_value=fake_runtime):
            execution = self.service.call_tool("dwi_execute_cleanup", {"execution_handle": execution_handle})
        recovery_handle = execution["item_results"][0]["recovery_handle"]
        status = self.service.call_tool("dwi_get_recovery_status", {"execution_handle": execution_handle})
        self.assertEqual(status["recoveries"][0]["recovery_handle"], recovery_handle)
        restored = self.service.call_tool("dwi_request_undo", {"recovery_handle": recovery_handle})
        self.assertEqual(restored["status"], "RESTORED")
        with self.assertRaises(McpServiceError) as context:
            self.service.call_tool("dwi_request_undo", {"recovery_handle": recovery_handle})
        self.assertEqual(context.exception.code, McpErrorCode.CONSUMED_HANDLE)


class McpSafetyIntegrationTests(unittest.TestCase):
    def test_mcp_smoke_uses_disposable_fixture_and_stops_before_agent_confirmation(self) -> None:
        result = run_mcp_smoke()
        self.assertTrue(result.imported)
        self.assertTrue(result.initialized)
        self.assertTrue(result.tools_listed)
        self.assertTrue(result.scanned)
        self.assertTrue(result.findings_inspected)
        self.assertTrue(result.human_confirmation_guarded)
        self.assertFalse(result.mutation_executed)

    def test_partial_scan_cannot_create_cleanup_review(self) -> None:
        scan = SystemScan(
            requested_roots=(ROOT,),
            root_observations=(RootObservation(
                ROOT,
                RootScope.ADDITIONAL_LOCAL,
                "partial",
                RootBoundary.LOCAL_DIRECTORY,
                RootStatus.PARTIAL,
                "observation failed",
            ),),
            workspace_findings=(_finding(),),
            global_storage_findings=(),
            git_observations=(),
            observation_failures=("fixture observation failed",),
            ambiguous_boundaries=(),
            termination=ScanTermination.COMPLETED,
            nodes_observed=1,
            files_observed=0,
        )
        service = McpService(scan_fn=lambda _options: scan)
        scan_handle = service.call_tool("dwi_scan_root", {"root": ROOT})["scan_handle"]
        finding_id = service.call_tool("dwi_list_findings", {"scan_handle": scan_handle})["findings"][0]["finding_id"]
        with self.assertRaises(McpServiceError) as context:
            service.call_tool("dwi_create_cleanup_review", {"scan_handle": scan_handle, "finding_ids": [finding_id]})
        self.assertEqual(context.exception.code, McpErrorCode.REVALIDATION_BLOCKED)

    def test_network_root_remains_denied_by_engine_scan_gate(self) -> None:
        result = McpService().call_tool("dwi_scan_root", {"root": "\\\\server\\share"})
        observation = result["summary"]["root_observations"][0]
        self.assertEqual(observation["status"], RootStatus.DENIED.value)
        self.assertEqual(result["findings_count"], 0)


class McpHandleStoreResourceTests(unittest.TestCase):
    def test_expiration_reclaims_payload_and_returns_stale(self) -> None:
        now = [0.0]

        class Payload:
            pass

        payload = Payload()
        payload_ref = weakref.ref(payload)
        store = OpaqueHandleStore(ttl_seconds=1, max_entries=2, clock=lambda: now[0])
        handle = store.issue(McpHandleType.SCAN, payload)
        del payload
        now[0] = 2.0
        with self.assertRaises(McpServiceError) as context:
            store.resolve(handle, McpHandleType.SCAN)
        self.assertEqual(context.exception.code, McpErrorCode.STALE_HANDLE)
        gc.collect()
        self.assertIsNone(payload_ref())
        self.assertEqual(store.live_entry_count, 0)

    def test_capacity_rejects_without_evicting_active_and_purge_frees_capacity(self) -> None:
        now = [0.0]
        store = OpaqueHandleStore(ttl_seconds=10, max_entries=2, clock=lambda: now[0])
        first = store.issue(McpHandleType.SCAN, object())
        store.issue(McpHandleType.SCAN, object())
        with self.assertRaises(McpServiceError) as context:
            store.issue(McpHandleType.SCAN, object())
        self.assertEqual(context.exception.code, McpErrorCode.RESOURCE_LIMIT)
        self.assertEqual(store.live_entry_count, 2)
        self.assertEqual(store.state(first, McpHandleType.SCAN), McpHandleState.ACTIVE)
        now[0] = 11.0
        replacement = store.issue(McpHandleType.SCAN, object())
        self.assertEqual(store.live_entry_count, 1)
        self.assertEqual(store.state(replacement, McpHandleType.SCAN), McpHandleState.ACTIVE)

    def test_consumed_handle_expires_even_when_consumed_lookup_is_allowed(self) -> None:
        now = [0.0]
        store = OpaqueHandleStore(ttl_seconds=1, max_entries=2, clock=lambda: now[0])
        handle = store.issue(McpHandleType.EXECUTION, object())
        store.consume(handle, McpHandleType.EXECUTION)
        self.assertEqual(store.state(handle, McpHandleType.EXECUTION, allow_consumed=True), McpHandleState.EXECUTING)
        now[0] = 2.0
        with self.assertRaises(McpServiceError) as context:
            store.resolve(handle, McpHandleType.EXECUTION, allow_consumed=True)
        self.assertEqual(context.exception.code, McpErrorCode.STALE_HANDLE)
        self.assertEqual(store.live_entry_count, 0)

    def test_tombstones_and_live_entries_remain_bounded(self) -> None:
        now = [0.0]
        store = OpaqueHandleStore(ttl_seconds=1, max_entries=3, clock=lambda: now[0])
        handles = [store.issue(McpHandleType.SCAN, object()) for _ in range(3)]
        self.assertEqual(store.live_entry_count, 3)
        now[0] = 2.0
        replacement = store.issue(McpHandleType.SCAN, object())
        self.assertEqual(store.live_entry_count, 1)
        self.assertLessEqual(store.tombstone_count, 3)
        self.assertEqual(store.state(replacement, McpHandleType.SCAN), McpHandleState.ACTIVE)
        for handle in handles:
            with self.assertRaises(McpServiceError) as context:
                store.resolve(handle, McpHandleType.SCAN)
            self.assertEqual(context.exception.code, McpErrorCode.STALE_HANDLE)


if __name__ == "__main__":
    unittest.main()
