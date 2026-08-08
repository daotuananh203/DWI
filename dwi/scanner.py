"""Bounded deterministic discovery of supported artifacts below one root."""

from __future__ import annotations

import os
import stat
from dataclasses import dataclass
from pathlib import Path

from .domain import RiskLabel
from .dispatcher import analyze_candidate
from .pipeline import Finding, evaluate_analysis
from .size import collect_size


_SUPPORTED_NAMES = frozenset({
    "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache", ".venv", "venv",
    "node_modules", "dist", "build", ".next",
})


class WorkspaceScanError(ValueError):
    pass


@dataclass(frozen=True)
class WorkspaceSummary:
    candidates_discovered: int
    findings_by_risk: tuple[tuple[str, int], ...]
    known_analyzed_bytes: int
    potentially_reclaimable_bytes: int
    incomplete_size_count: int
    observation_failure_count: int


@dataclass(frozen=True)
class WorkspaceScan:
    root: str
    findings: tuple[Finding, ...]
    observation_failures: tuple[str, ...] = ()
    ambiguous_paths: tuple[str, ...] = ()
    protected_git_paths: tuple[str, ...] = ()

    @property
    def summary(self) -> WorkspaceSummary:
        counts = {label.value: 0 for label in RiskLabel}
        reclaimable = 0
        known = 0
        incomplete = 0
        failures = len(self.observation_failures)
        for finding in self.findings:
            counts[finding.risk_label.value] += 1
            known += finding.size.known_bytes
            if not finding.size.complete:
                incomplete += 1
            failures += len(finding.size.observation_failures)
            if (
                finding.candidate_selection.candidate is not None
                and finding.safety_decision is not None
                and finding.safety_decision.risk_label in {RiskLabel.SAFE, RiskLabel.REGENERATABLE}
                and finding.safety_decision.action_eligibility.value == "eligible_for_explicit_action"
                and finding.size.complete
            ):
                reclaimable += finding.size.known_bytes
        return WorkspaceSummary(
            candidates_discovered=len(self.findings),
            findings_by_risk=tuple((label.value, counts[label.value]) for label in RiskLabel),
            known_analyzed_bytes=known,
            potentially_reclaimable_bytes=reclaimable,
            incomplete_size_count=incomplete,
            observation_failure_count=failures,
        )


def _is_reparse(metadata: os.stat_result) -> bool:
    return bool(getattr(metadata, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))


def scan_workspace(root: str | os.PathLike[str]) -> WorkspaceScan:
    """Discover supported names under exactly one explicit ordinary directory."""
    root_path = Path(root)
    try:
        root_metadata = os.lstat(root_path)
    except OSError as error:
        raise WorkspaceScanError(f"workspace root could not be observed: {root_path}") from error
    if not stat.S_ISDIR(root_metadata.st_mode) or stat.S_ISLNK(root_metadata.st_mode) or _is_reparse(root_metadata):
        raise WorkspaceScanError("workspace root must be an ordinary directory")

    findings: list[Finding] = []
    failures: list[str] = []
    ambiguous: list[str] = []
    protected: list[str] = []
    seen: set[tuple[int, int]] = set()
    stack = [root_path]
    while stack:
        current = stack.pop()
        try:
            metadata = os.lstat(current)
            identity = (getattr(metadata, "st_dev", 0), getattr(metadata, "st_ino", 0))
            if identity in seen:
                ambiguous.append(str(current))
                continue
            seen.add(identity)
            entries = sorted(os.scandir(current), key=lambda item: (item.name.casefold(), item.name))
        except (OSError, ValueError) as error:
            failures.append(f"{current}: {type(error).__name__}")
            continue
        for entry in reversed(entries):
            child = Path(entry.path)
            name = entry.name
            try:
                child_metadata = entry.stat(follow_symlinks=False)
                if entry.is_symlink() or _is_reparse(child_metadata):
                    ambiguous.append(str(child))
                    continue
                if name == ".git":
                    protected.append(str(child))
                    continue
                if name in _SUPPORTED_NAMES and entry.is_dir(follow_symlinks=False):
                    result = analyze_candidate(child)
                    if result is not None:
                        findings.append(evaluate_analysis(result, size=collect_size(child)))
                    continue
                if entry.is_dir(follow_symlinks=False):
                    stack.append(child)
            except (OSError, ValueError) as error:
                failures.append(f"{child}: {type(error).__name__}")
    findings.sort(key=lambda item: (item.path.casefold(), item.path))
    return WorkspaceScan(
        root=str(root_path),
        findings=tuple(findings),
        observation_failures=tuple(sorted(failures)),
        ambiguous_paths=tuple(sorted(ambiguous)),
        protected_git_paths=tuple(sorted(protected)),
    )
