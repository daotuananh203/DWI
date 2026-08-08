"""Deterministic human and JSON reporting for workspace analysis."""

from __future__ import annotations

import dataclasses
import json
from enum import Enum
from typing import Any

from .pipeline import Finding
from .scanner import WorkspaceScan


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
