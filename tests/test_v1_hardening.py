from __future__ import annotations

import unittest
from pathlib import Path

from dwi import (
    ActivityState,
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
    ReclaimPriority,
    RegenerabilityState,
    RegenerationCost,
    ReachabilityState,
    RiskLabel,
    SafetyContext,
    evaluate_safety,
    escalate_risk,
)
from dwi.desktop import DESKTOP_VERSION
from dwi.mcp import McpServer, McpService
from dwi.mcp.models import McpServiceError
from dwi.mcp.pagination import page_items
from dwi.mcp.schemas import MCP_MAX_PAGE_SIZE, TOOL_DEFINITIONS
from dwi.scan_control import (
    DEFAULT_MAX_FILES,
    DEFAULT_MAX_NODES,
    DEFAULT_MAX_SECONDS,
    MAX_SCAN_FILES,
    MAX_SCAN_NODES,
    MAX_SCAN_SECONDS,
    ScanLimits,
)
from dwi.version import __version__


REQUIRED_KEYS = ("artifact_identity", "provenance", "regenerability", "reachability", "activity", "protection")


def _bundle(replacement: Evidence | None = None) -> EvidenceBundle:
    observations = [Evidence(
        key=key,
        source="v1-hardening",
        description=f"Complete synthetic evidence for {key}.",
        observation_status=ObservationStatus.OBSERVED,
        polarity=EvidencePolarity.SUPPORTS,
        confidence=Confidence.HIGH,
    ) for key in REQUIRED_KEYS]
    if replacement is not None:
        observations = [item for item in observations if item.key != replacement.key]
        observations.append(replacement)
    return EvidenceBundle(tuple(observations), tuple(EvidenceRequirement(key, Confidence.HIGH) for key in REQUIRED_KEYS))


def _context(*, evidence: EvidenceBundle | None = None, reachability=ReachabilityState.CONFIRMED_UNREFERENCED, protection=ProtectionClass.ORDINARY, activity=ActivityState.INACTIVE, regenerability=RegenerabilityState.REPRODUCIBLE) -> SafetyContext:
    candidate = CleanupCandidate(
        ObservedNode("C:\\synthetic\\artifact", NodeKind.DIRECTORY, protection),
        _bundle(),
    )
    return SafetyContext(
        candidate=candidate,
        evidence=evidence or _bundle(),
        provenance=Provenance("python", "synthetic", Confidence.HIGH),
        regenerability=regenerability,
        regeneration_cost=RegenerationCost.LOW,
        reachability=reachability,
        activity=activity,
        protection=protection,
        reclaim_priority=ReclaimPriority.HIGH,
    )


class V1ResourceAndPolicyTests(unittest.TestCase):
    def test_global_scan_limits_are_finite_typed_and_hard_bounded(self) -> None:
        self.assertEqual(DEFAULT_MAX_SECONDS, MAX_SCAN_SECONDS)
        self.assertEqual(DEFAULT_MAX_NODES, MAX_SCAN_NODES)
        self.assertEqual(DEFAULT_MAX_FILES, MAX_SCAN_FILES)
        for kwargs in (
            {"max_seconds": float("nan")},
            {"max_seconds": float("inf")},
            {"max_seconds": float("-inf")},
            {"max_seconds": True},
            {"max_nodes": True},
            {"max_nodes": 1.5},
            {"max_seconds": 0},
            {"max_nodes": 0},
            {"max_files": 0},
            {"max_files": 100_001},
            {"max_seconds": MAX_SCAN_SECONDS + 1},
        ):
            with self.subTest(kwargs=kwargs):
                with self.assertRaises(ValueError):
                    ScanLimits(**kwargs)
        ScanLimits(max_seconds=MAX_SCAN_SECONDS, max_nodes=MAX_SCAN_NODES, max_files=MAX_SCAN_FILES)
        self.assertEqual(
            ScanLimits(),
            ScanLimits(max_seconds=DEFAULT_MAX_SECONDS, max_nodes=DEFAULT_MAX_NODES, max_files=DEFAULT_MAX_FILES),
        )
        self.assertEqual(
            ScanLimits(max_seconds=None, max_nodes=None, max_files=None),
            ScanLimits(max_seconds=DEFAULT_MAX_SECONDS, max_nodes=DEFAULT_MAX_NODES, max_files=DEFAULT_MAX_FILES),
        )

    def test_policy_cross_layer_safety_floor_and_monotonicity(self) -> None:
        missing = EvidenceBundle((), tuple(EvidenceRequirement(key, Confidence.HIGH) for key in REQUIRED_KEYS))
        self.assertEqual(evaluate_safety(_context(evidence=missing)).risk_label, RiskLabel.REVIEW_REQUIRED)
        failed = Evidence("reachability", "v1-hardening", "failed", ObservationStatus.FAILED, EvidencePolarity.UNKNOWN, Confidence.UNKNOWN)
        self.assertEqual(evaluate_safety(_context(evidence=_bundle(failed))).risk_label, RiskLabel.REVIEW_REQUIRED)
        for reachability in (ReachabilityState.CONFIRMED_REFERENCED, ReachabilityState.UNKNOWN):
            with self.subTest(reachability=reachability):
                self.assertGreaterEqual(evaluate_safety(_context(reachability=reachability)).risk_label.rank, RiskLabel.REVIEW_REQUIRED.rank)
        self.assertGreaterEqual(evaluate_safety(_context(protection=ProtectionClass.SYSTEM_PROTECTED)).risk_label.rank, RiskLabel.NEVER_DELETE.rank)
        self.assertEqual(evaluate_safety(_context(regenerability=RegenerabilityState.REPRODUCIBLE, activity=ActivityState.UNKNOWN)).risk_label, RiskLabel.REVIEW_REQUIRED)
        for current in RiskLabel:
            for proposed in RiskLabel:
                self.assertGreaterEqual(escalate_risk(current, proposed).rank, current.rank)

    def test_mcp_tool_schemas_are_bounded_and_authority_free(self) -> None:
        names = {str(tool["name"]) for tool in TOOL_DEFINITIONS}
        self.assertNotIn("dwi_confirm_cleanup", names)
        forbidden = {"delete_file", "remove_file", "quarantine_path", "restore_to"}
        self.assertTrue(forbidden.isdisjoint(names))
        by_name = {str(tool["name"]): tool for tool in TOOL_DEFINITIONS}
        self.assertEqual(by_name["dwi_scan_system"]["inputSchema"]["properties"]["roots"]["maxItems"], 32)
        self.assertEqual(by_name["dwi_create_cleanup_review"]["inputSchema"]["properties"]["finding_ids"]["maxItems"], 256)
        for name in ("dwi_list_findings", "dwi_get_recovery_status"):
            self.assertEqual(by_name[name]["inputSchema"]["properties"]["limit"]["maximum"], MCP_MAX_PAGE_SIZE)

    def test_pagination_cursor_is_read_only_and_stale_cursors_fail(self) -> None:
        first = page_items(tuple(range(3)), key="fixture", limit=1, maximum=10)
        self.assertEqual(first.items, (0,))
        second = page_items(tuple(range(3)), key="fixture", limit=10, cursor=first.next_cursor, maximum=10)
        self.assertEqual(second.items, (1, 2))
        with self.assertRaises(McpServiceError):
            page_items(tuple(range(3)), key="changed", limit=1, cursor=first.next_cursor, maximum=10)

    def test_version_is_single_source_across_desktop_cli_mcp_and_metadata(self) -> None:
        self.assertEqual(__version__, "1.0.0")
        self.assertEqual(DESKTOP_VERSION, __version__)
        mcp = McpServer(McpService()).handle_message({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
        assert mcp is not None
        self.assertEqual(mcp["result"]["serverInfo"]["version"], __version__)
        metadata = Path("pyproject.toml").read_text(encoding="utf-8")
        self.assertIn("dynamic = [\"version\"]", metadata)
        self.assertIn("dwi.version.__version__", metadata)


if __name__ == "__main__":
    unittest.main()
