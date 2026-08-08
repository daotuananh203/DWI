"""Deterministic human and JSON reporting for workspace analysis."""

from __future__ import annotations

import dataclasses
import json
from enum import Enum
from typing import Any

from .pipeline import Finding
from .scanner import WorkspaceScan
from .system_scan import RootStatus, SystemScan


def _json_value(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    if dataclasses.is_dataclass(value):
        return {field.name: _json_value(getattr(value, field.name)) for field in dataclasses.fields(value)}
    if isinstance(value, (tuple, list)):
        return [_json_value(item) for item in value]
    if isinstance(value, (set, frozenset)):
        return sorted(_json_value(item) for item in value)
    if isinstance(value, dict):
        return {str(key): _json_value(item) for key, item in sorted(value.items(), key=lambda item: str(item[0]))}
    return value


def finding_to_dict(finding: Finding) -> dict[str, Any]:
    """Serialize the public finding schema explicitly for audit stability."""
    return {
        "artifact": finding.artifact.value,
        "path": finding.path,
        "risk_label": finding.risk_label.value,
        "action_eligibility": finding.action_eligibility.value,
        "regenerability": finding.interpretation.regenerability.value,
        "candidate_eligibility": finding.candidate_selection.eligibility.value,
        "rejection_reason": finding.candidate_selection.reason,
        "size": {
            "known_bytes": finding.size.known_bytes,
            "complete": finding.size.complete,
            "observation_failures": list(finding.size.observation_failures),
            "links_skipped": list(finding.size.links_skipped),
        },
        "summary": finding.summary,
        "evidence": _json_value(finding.evidence),
        "interpretation": _json_value(finding.interpretation),
        "safety_decision": _json_value(finding.safety_decision),
        "rule_trace": _json_value(finding.rule_trace),
    }


def scan_to_dict(scan: WorkspaceScan) -> dict[str, Any]:
    result = {
        "root": scan.root,
        "findings": [finding_to_dict(finding) for finding in scan.findings],
        "observation_failures": list(scan.observation_failures),
        "ambiguous_paths": list(scan.ambiguous_paths),
        "protected_git_paths": list(scan.protected_git_paths),
        "git_observations": [_json_value(observation) for observation in scan.git_observations],
    }
    result["summary"] = _json_value(scan.summary)
    return result


def json_report(scan: WorkspaceScan) -> str:
    return json.dumps(scan_to_dict(scan), indent=2, sort_keys=True) + "\n"


def system_to_dict(scan: SystemScan) -> dict[str, Any]:
    roots = [
        {
            "path": item.path,
            "scope": item.scope.value,
            "label": item.label,
            "boundary": item.boundary.value,
            "status": item.status.value,
            "reason": item.reason,
            "artifact": item.artifact.value if item.artifact is not None else None,
        }
        for item in scan.root_observations
    ]
    return {
        "requested_roots": list(scan.requested_roots),
        "roots_actually_scanned": [item["path"] for item in roots if item["status"] in {RootStatus.COMPLETE.value, RootStatus.PARTIAL.value}],
        "roots_denied_or_skipped": [item for item in roots if item["status"] in {RootStatus.DENIED.value, RootStatus.SKIPPED.value, RootStatus.FAILED.value}],
        "root_observations": roots,
        "workspace_findings": [finding_to_dict(finding) for finding in scan.workspace_findings],
        "global_storage_findings": [finding_to_dict(finding) for finding in scan.global_storage_findings],
        "findings": [finding_to_dict(finding) for finding in scan.findings],
        "protected_git_paths": [observation.node.path for observation in scan.git_observations],
        "git_observations": [_json_value(observation) for observation in scan.git_observations],
        "observation_failures": list(scan.observation_failures),
        "ambiguous_boundaries": list(scan.ambiguous_boundaries),
        "denied_network_boundaries": [
            {"path": item.path, "boundary": item.boundary.value, "reason": item.reason}
            for item in scan.denied_network_boundaries
        ],
        "scan_metadata": {
            "termination": scan.termination.value,
            "nodes_observed": scan.nodes_observed,
            "files_observed": scan.files_observed,
        },
        "summary": _json_value(scan.summary),
    }


def json_system_report(scan: SystemScan) -> str:
    return json.dumps(system_to_dict(scan), indent=2, sort_keys=True) + "\n"


def table_report(scan: WorkspaceScan) -> str:
    headers = ("PATH", "ARTIFACT", "SIZE", "REGENERABILITY", "RISK", "ACTION", "SUMMARY")
    rows = [headers]
    for finding in scan.findings:
        size = (
            str(finding.size.known_bytes)
            if finding.size.complete
            else f"{finding.size.known_bytes} (partial)"
        )
        rows.append((
            finding.path,
            finding.artifact.value,
            size,
            finding.interpretation.regenerability.value,
            finding.risk_label.value,
            finding.action_eligibility.value,
            finding.summary,
        ))
    widths = [max(len(row[index]) for row in rows) for index in range(len(headers))]
    lines = ["  ".join(value.ljust(widths[index]) for index, value in enumerate(rows[0]))]
    lines.append("  ".join("-" * width for width in widths))
    lines.extend("  ".join(value.ljust(widths[index]) for index, value in enumerate(row)) for row in rows[1:])
    summary = scan.summary
    lines.append("")
    lines.append(f"Candidates: {summary.candidates_discovered}")
    lines.append(f"Known bytes: {summary.known_analyzed_bytes}")
    lines.append(f"Potentially reclaimable bytes: {summary.potentially_reclaimable_bytes}")
    lines.append(f"Incomplete size observations: {summary.incomplete_size_count}")
    lines.append(f"Observation failures: {summary.observation_failure_count}")
    return "\n".join(lines) + "\n"


def _finding_rows(findings: tuple[Finding, ...]) -> list[tuple[str, ...]]:
    return [
        (
            finding.path,
            finding.artifact.value,
            str(finding.size.known_bytes) if finding.size.complete else f"{finding.size.known_bytes} (partial)",
            finding.interpretation.regenerability.value,
            finding.risk_label.value,
            finding.action_eligibility.value,
            finding.summary,
        )
        for finding in findings
    ]


def _render_finding_section(title: str, findings: tuple[Finding, ...]) -> list[str]:
    headers = ("PATH", "ARTIFACT", "SIZE", "REGENERABILITY", "RISK", "ACTION", "SUMMARY")
    rows = [headers, *_finding_rows(findings)]
    widths = [max(len(row[index]) for row in rows) for index in range(len(headers))]
    lines = [title, "  ".join(value.ljust(widths[index]) for index, value in enumerate(headers))]
    lines.append("  ".join("-" * width for width in widths))
    lines.extend("  ".join(value.ljust(widths[index]) for index, value in enumerate(row)) for row in rows[1:])
    return lines


def table_system_report(scan: SystemScan) -> str:
    lines = _render_finding_section("Workspace artifacts", scan.workspace_findings)
    lines.append("")
    lines.extend(_render_finding_section("Global developer storage", scan.global_storage_findings))
    lines.append("")
    lines.append("Roots")
    for root in scan.root_observations:
        lines.append(f"{root.status.value}: {root.path} ({root.reason})")
    if scan.denied_network_boundaries:
        lines.append("")
        lines.append("Denied network boundaries")
        lines.extend(f"{item.path}: {item.reason}" for item in scan.denied_network_boundaries[:5])
        if len(scan.denied_network_boundaries) > 5:
            lines.append(f"... {len(scan.denied_network_boundaries) - 5} more; see JSON for full detail")
    summary = scan.summary
    size_failures = [
        failure
        for finding in scan.findings
        for failure in finding.size.observation_failures
    ]
    important_failures = tuple(sorted(set(scan.observation_failures).union(size_failures)))
    lines.extend(
        (
            "",
            f"Protected Git paths: {len(scan.git_observations)}",
            f"Ambiguous/reparse boundaries: {len(scan.ambiguous_boundaries)}",
            f"Denied network boundaries: {len(scan.denied_network_boundaries)}",
            f"Partial: {'yes' if scan.termination.value != 'completed' else 'no'}",
            f"Termination: {scan.termination.value}",
            f"Known bytes: {summary.known_analyzed_bytes}",
            f"Partial known bytes: {summary.partial_known_bytes}",
            f"Potentially reclaimable bytes: {summary.potentially_reclaimable_bytes}",
            f"Incomplete size observations: {summary.incomplete_size_count}",
            f"Observation failures: {summary.observation_failure_count}",
        )
    )
    if important_failures:
        lines.append("Important observation failures:")
        lines.extend(f"- {failure}" for failure in important_failures[:5])
        if len(important_failures) > 5:
            lines.append(f"- ... {len(important_failures) - 5} more; see JSON for full detail")
    return "\n".join(lines) + "\n"
