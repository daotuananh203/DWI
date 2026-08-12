"""Bounded deterministic discovery of supported artifacts below one root."""

from __future__ import annotations

import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from .domain import RiskLabel
from .dispatcher import analyze_candidate
from .git_context import GitContextObservation, observe_git_path
from .pipeline import Finding, evaluate_analysis
from .scan_control import ScanBudget, ScanLimits, ScanTermination
from .size import collect_size


_SUPPORTED_NAMES = frozenset({
    "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache", ".venv", "venv",
    "node_modules", "dist", "build", ".next",
})
_DISPOSABLE_MARKER = ".dwi-disposable-root"
_DISPOSABLE_MARKER_CONTENT = "DWI-DISPOSABLE-ROOT-v0.3\n"


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
    git_observations: tuple[GitContextObservation, ...] = ()
    termination: ScanTermination = ScanTermination.COMPLETED
    nodes_observed: int = 0
    files_observed: int = 0

    @property
    def protected_git_paths(self) -> tuple[str, ...]:
        """Backward-compatible path view of structured Git observations."""
        return tuple(sorted(observation.node.path for observation in self.git_observations))

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


def _metadata_identity(metadata: os.stat_result) -> tuple[int, int, int, bool]:
    return (
        getattr(metadata, "st_dev", 0),
        getattr(metadata, "st_ino", 0),
        stat.S_IFMT(metadata.st_mode),
        _is_reparse(metadata),
    )


def _metadata_matches(first: os.stat_result, second: os.stat_result) -> bool:
    first_identity = _metadata_identity(first)
    second_identity = _metadata_identity(second)
    if first_identity[2:] != second_identity[2:]:
        return False
    if first_identity[:2] == (0, 0) or second_identity[:2] == (0, 0):
        return True
    return first_identity[:2] == second_identity[:2]


def _within_root(root: Path, path: Path) -> bool:
    try:
        return os.path.commonpath((os.path.abspath(root), os.path.abspath(path))) == os.path.abspath(root)
    except ValueError:
        return False


def _has_disposable_root_marker(root: Path) -> bool:
    """Verify the exact ordinary-file marker used by disposable QA roots."""

    try:
        with os.scandir(root) as entries:
            marker_entry = next((entry for entry in entries if entry.name == _DISPOSABLE_MARKER), None)
        if marker_entry is None:
            return False
        metadata = marker_entry.stat(follow_symlinks=False)
        if not stat.S_ISREG(metadata.st_mode) or marker_entry.is_symlink() or _is_reparse(metadata):
            return False
        return Path(marker_entry.path).read_text(encoding="utf-8") == _DISPOSABLE_MARKER_CONTENT
    except (OSError, UnicodeError):
        return False


def scan_workspace(
    root: str | os.PathLike[str],
    *,
    limits: ScanLimits | None = None,
    cancellation: Callable[[], bool] | None = None,
    budget: ScanBudget | None = None,
) -> WorkspaceScan:
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
    git_observations: list[GitContextObservation] = []
    active_budget = budget or ScanBudget(limits=limits or ScanLimits(), cancellation=cancellation)
    disposable_root = _has_disposable_root_marker(root_path)
    seen: set[tuple[int, int]] = set()
    stack = [root_path]
    while stack:
        if active_budget.stopped():
            break
        current = stack.pop()
        if not active_budget.observe_node():
            break
        try:
            metadata = os.lstat(current)
            if not _within_root(root_path, current):
                ambiguous.append(str(current))
                failures.append(f"{current}: outside-approved-root")
                continue
            if stat.S_ISLNK(metadata.st_mode):
                ambiguous.append(str(current))
                failures.append(f"{current}: current-node-symlink")
                continue
            if _is_reparse(metadata):
                ambiguous.append(str(current))
                failures.append(f"{current}: current-node-reparse")
                continue
            if not stat.S_ISDIR(metadata.st_mode):
                ambiguous.append(str(current))
                failures.append(f"{current}: current-node-not-directory")
                continue
            identity = (getattr(metadata, "st_dev", 0), getattr(metadata, "st_ino", 0))
            if identity in seen:
                ambiguous.append(str(current))
                continue
            seen.add(identity)
            pre_traversal_metadata = os.lstat(current)
            if stat.S_ISLNK(pre_traversal_metadata.st_mode):
                ambiguous.append(str(current))
                failures.append(f"{current}: current-node-symlink")
                continue
            if _is_reparse(pre_traversal_metadata):
                ambiguous.append(str(current))
                failures.append(f"{current}: current-node-reparse")
                continue
            if not stat.S_ISDIR(pre_traversal_metadata.st_mode):
                ambiguous.append(str(current))
                failures.append(f"{current}: current-node-not-directory")
                continue
            if not _metadata_matches(metadata, pre_traversal_metadata):
                ambiguous.append(str(current))
                failures.append(f"{current}: traversal-race")
                continue
            entries = sorted(os.scandir(current), key=lambda item: (item.name.casefold(), item.name))
            after_scan = os.lstat(current)
            if not _metadata_matches(metadata, after_scan):
                ambiguous.append(str(current))
                failures.append(f"{current}: traversal-race")
                continue
        except (OSError, ValueError) as error:
            ambiguous.append(str(current))
            failures.append(f"{current}: {type(error).__name__}")
            continue
        for entry in reversed(entries):
            if not active_budget.observe_node():
                break
            child = Path(entry.path)
            name = entry.name
            try:
                if name == ".git":
                    git_observations.append(observe_git_path(child))
                    continue
                child_metadata = os.lstat(child)
                if not _within_root(root_path, child):
                    ambiguous.append(str(child))
                    failures.append(f"{child}: outside-approved-root")
                    continue
                child_after = os.lstat(child)
                if not _metadata_matches(child_metadata, child_after):
                    ambiguous.append(str(child))
                    failures.append(f"{child}: traversal-race")
                    continue
                child_metadata = child_after
                if stat.S_ISREG(child_metadata.st_mode) and not active_budget.observe_node(is_file=True):
                    break
                if stat.S_ISLNK(child_metadata.st_mode) or _is_reparse(child_metadata):
                    ambiguous.append(str(child))
                    continue
                if name in _SUPPORTED_NAMES and stat.S_ISDIR(child_metadata.st_mode):
                    result = analyze_candidate(child, disposable_root=disposable_root)
                    if result is not None:
                        findings.append(evaluate_analysis(result, size=collect_size(child, budget=active_budget)))
                    continue
                if stat.S_ISDIR(child_metadata.st_mode):
                    stack.append(child)
            except (OSError, ValueError) as error:
                failures.append(f"{child}: {type(error).__name__}")
    findings.sort(key=lambda item: (item.path.casefold(), item.path))
    return WorkspaceScan(
        root=str(root_path),
        findings=tuple(findings),
        observation_failures=tuple(sorted(failures)),
        ambiguous_paths=tuple(sorted(ambiguous)),
        git_observations=tuple(sorted(git_observations, key=lambda item: (item.node.path.casefold(), item.node.path))),
        termination=active_budget.termination,
        nodes_observed=active_budget.nodes_observed,
        files_observed=active_budget.files_observed,
    )
