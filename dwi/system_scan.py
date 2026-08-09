"""Bounded Windows developer-storage discovery and the Scan Safety Gate."""

from __future__ import annotations

import ctypes
import ntpath
import os
import stat
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Callable

from .contracts import ArtifactKind
from .dispatcher import AnalysisResult
from .global_storage import inspect_global_storage, interpret_global_storage
from .git_context import GitContextObservation
from .pipeline import Finding, evaluate_analysis
from .scan_control import (
    DEFAULT_MAX_FILES,
    DEFAULT_MAX_NODES,
    DEFAULT_MAX_SECONDS,
    ScanBudget,
    ScanLimits,
    ScanTermination,
)
from .scanner import scan_workspace
from .size import collect_size
from .domain import ObservationStatus


class RootBoundary(str, Enum):
    LOCAL_FIXED_DRIVE = "local_fixed_drive"
    LOCAL_DIRECTORY = "local_directory"
    UNC = "unc"
    NETWORK = "network"
    MAPPED_DRIVE = "mapped_drive"
    REMOVABLE_DRIVE = "removable_drive"
    UNKNOWN = "unknown"


class RootScope(str, Enum):
    FIXED_DRIVE = "fixed_drive"
    USER_PROFILE = "user_profile"
    ADDITIONAL_LOCAL = "additional_local"
    GLOBAL_STORAGE = "global_storage"


class RootStatus(str, Enum):
    COMPLETE = "complete"
    # Retained for input compatibility only. It is intentionally not an alias
    # of COMPLETE: callers cannot turn an unclassified "scanned" observation
    # into trusted mutation completeness.
    SCANNED = "scanned"
    PARTIAL = "partial"
    DENIED = "denied"
    SKIPPED = "skipped"
    FAILED = "failed"


@dataclass(frozen=True)
class RootRequest:
    path: str
    scope: RootScope
    label: str
    artifact: ArtifactKind | None = None


@dataclass(frozen=True)
class RootObservation:
    path: str
    scope: RootScope
    label: str
    boundary: RootBoundary
    status: RootStatus
    reason: str
    artifact: ArtifactKind | None = None


@dataclass(frozen=True)
class SystemScanOptions:
    """Explicit controls for one system scan.

    Supplying ``additional_roots`` is the preferred way to test or target a
    bounded local directory. With additional roots present, automatic drive
    and profile discovery is disabled unless explicitly enabled.
    """

    additional_roots: tuple[str, ...] = ()
    drive: str | None = None
    include_fixed_drives: bool = True
    include_user_profile: bool = True
    include_global_storage: bool = True
    global_storage_roots: tuple[RootRequest, ...] = ()
    allow_network: bool = False
    limits: ScanLimits = field(
        default_factory=lambda: ScanLimits(
            max_seconds=DEFAULT_MAX_SECONDS,
            max_nodes=DEFAULT_MAX_NODES,
            max_files=DEFAULT_MAX_FILES,
        )
    )
    cancellation: Callable[[], bool] | None = None


@dataclass(frozen=True)
class SystemSummary:
    workspace_findings: int
    global_storage_findings: int
    known_analyzed_bytes: int
    partial_known_bytes: int
    potentially_reclaimable_bytes: int
    incomplete_size_count: int
    observation_failure_count: int


@dataclass(frozen=True)
class SystemScan:
    requested_roots: tuple[str, ...]
    root_observations: tuple[RootObservation, ...]
    workspace_findings: tuple[Finding, ...]
    global_storage_findings: tuple[Finding, ...]
    git_observations: tuple[GitContextObservation, ...]
    observation_failures: tuple[str, ...]
    ambiguous_boundaries: tuple[str, ...]
    termination: ScanTermination
    nodes_observed: int
    files_observed: int

    @property
    def findings(self) -> tuple[Finding, ...]:
        return tuple(sorted(
            self.workspace_findings + self.global_storage_findings,
            key=lambda item: (item.path.casefold(), item.path, item.artifact.value),
        ))

    @property
    def denied_network_boundaries(self) -> tuple[RootObservation, ...]:
        return tuple(
            item for item in self.root_observations
            if item.status is RootStatus.DENIED
            and item.boundary in {RootBoundary.UNC, RootBoundary.NETWORK, RootBoundary.MAPPED_DRIVE}
        )

    @property
    def summary(self) -> SystemSummary:
        known = 0
        partial = 0
        reclaimable = 0
        incomplete = 0
        failures = set(self.observation_failures)
        for finding in self.findings:
            known += finding.size.known_bytes
            if not finding.size.complete:
                partial += finding.size.known_bytes
                incomplete += 1
            failures.update(_finding_observation_failures(finding))
            if (
                finding.candidate_selection.candidate is not None
                and finding.safety_decision is not None
                and finding.safety_decision.risk_label.value in {"safe", "regeneratable"}
                and finding.safety_decision.action_eligibility.value == "eligible_for_explicit_action"
                and finding.size.complete
            ):
                reclaimable += finding.size.known_bytes
        return SystemSummary(
            workspace_findings=len(self.workspace_findings),
            global_storage_findings=len(self.global_storage_findings),
            known_analyzed_bytes=known,
            partial_known_bytes=partial,
            potentially_reclaimable_bytes=reclaimable,
            incomplete_size_count=incomplete,
            observation_failure_count=len(failures),
        )


class SystemScanError(ValueError):
    pass


def _finding_observation_failures(finding: Finding) -> tuple[str, ...]:
    failures = set(finding.size.observation_failures)
    failure_statuses = {
        ObservationStatus.FAILED,
        ObservationStatus.TIMED_OUT,
        ObservationStatus.INACCESSIBLE,
    }
    failures.update(
        f"{finding.path}: {observation.key}: {observation.description}"
        for observation in finding.evidence.observations
        if observation.observation_status in failure_statuses
    )
    return tuple(sorted(failures))


def _is_unc(path: str) -> bool:
    return path.startswith(("\\\\", "//"))


def _windows_drive_type(root: str) -> int | None:
    if os.name != "nt":
        return None
    try:
        return int(ctypes.windll.kernel32.GetDriveTypeW(root))
    except (AttributeError, OSError):
        return None


def classify_root(path: str | os.PathLike[str]) -> RootBoundary:
    raw = os.fspath(path)
    if _is_unc(raw):
        return RootBoundary.UNC
    drive, _ = ntpath.splitdrive(raw)
    if drive:
        drive_type = _windows_drive_type(drive + "\\")
        if drive_type == 3:
            return RootBoundary.LOCAL_FIXED_DRIVE
        if drive_type == 4:
            return RootBoundary.MAPPED_DRIVE
        if drive_type == 2:
            return RootBoundary.REMOVABLE_DRIVE
        if drive_type == 1:
            return RootBoundary.UNKNOWN
        if drive_type == 0:
            return RootBoundary.UNKNOWN
        if drive_type is None and os.name == "nt":
            return RootBoundary.UNKNOWN
        return RootBoundary.LOCAL_FIXED_DRIVE
    if os.path.isabs(raw):
        return RootBoundary.LOCAL_DIRECTORY
    return RootBoundary.UNKNOWN


def _normalize_path(path: str | os.PathLike[str]) -> str:
    raw = os.fspath(path)
    drive, tail = ntpath.splitdrive(raw)
    if drive:
        if not tail:
            tail = "\\"
        return ntpath.normpath(drive + tail)
    return os.path.abspath(os.path.normpath(raw))


def _same_or_within(child: str, parent: str) -> bool:
    child_norm = os.path.normcase(os.path.abspath(child))
    parent_norm = os.path.normcase(os.path.abspath(parent))
    try:
        return os.path.commonpath((child_norm, parent_norm)) == parent_norm
    except ValueError:
        return False


def _fixed_drive_roots() -> tuple[str, ...]:
    if os.name != "nt":
        return ()
    try:
        mask = int(ctypes.windll.kernel32.GetLogicalDrives())
    except (AttributeError, OSError):
        return ()
    roots: list[str] = []
    for index in range(26):
        if mask & (1 << index):
            drive = f"{chr(ord('A') + index)}:\\"
            if classify_root(drive) is RootBoundary.LOCAL_FIXED_DRIVE:
                roots.append(drive)
    return tuple(roots)


def _profile_root() -> Path | None:
    value = os.environ.get("USERPROFILE")
    if value:
        return Path(value)
    try:
        return Path.home()
    except (OSError, RuntimeError):
        return None


def approved_global_storage_roots(profile: Path | None = None) -> tuple[RootRequest, ...]:
    profile = profile or _profile_root()
    if profile is None:
        return ()
    local_app_data = Path(os.environ.get("LOCALAPPDATA", profile / "AppData" / "Local"))
    app_data = Path(os.environ.get("APPDATA", profile / "AppData" / "Roaming"))
    candidates = (
        (local_app_data / "pip" / "Cache", RootScope.GLOBAL_STORAGE, "pip-cache", ArtifactKind.PIP_CACHE),
        (profile / ".cache" / "pip", RootScope.GLOBAL_STORAGE, "pip-cache", ArtifactKind.PIP_CACHE),
        (local_app_data / "uv" / "cache", RootScope.GLOBAL_STORAGE, "uv-cache", ArtifactKind.UV_CACHE),
        (profile / ".cache" / "uv", RootScope.GLOBAL_STORAGE, "uv-cache", ArtifactKind.UV_CACHE),
        (local_app_data / "npm-cache", RootScope.GLOBAL_STORAGE, "npm-cache", ArtifactKind.NPM_CACHE),
        (app_data / "npm-cache", RootScope.GLOBAL_STORAGE, "npm-cache", ArtifactKind.NPM_CACHE),
        (local_app_data / "pnpm" / "store", RootScope.GLOBAL_STORAGE, "pnpm-store", ArtifactKind.PNPM_CACHE),
        (profile / ".pnpm-store", RootScope.GLOBAL_STORAGE, "pnpm-store", ArtifactKind.PNPM_CACHE),
        (local_app_data / "Yarn" / "Cache", RootScope.GLOBAL_STORAGE, "yarn-cache", ArtifactKind.YARN_CACHE),
        (profile / ".cache" / "yarn", RootScope.GLOBAL_STORAGE, "yarn-cache", ArtifactKind.YARN_CACHE),
    )
    unique: dict[tuple[str, ArtifactKind], RootRequest] = {}
    for path, scope, label, artifact in candidates:
        normalized = _normalize_path(path)
        unique[(os.path.normcase(normalized), artifact)] = RootRequest(normalized, scope, label, artifact)
    return tuple(sorted(unique.values(), key=lambda item: (item.path.casefold(), item.path, item.artifact.value if item.artifact else "")))


def _requests(options: SystemScanOptions) -> tuple[RootRequest, ...]:
    requests: list[RootRequest] = []
    if options.drive:
        requests.append(RootRequest(_normalize_path(options.drive), RootScope.FIXED_DRIVE, f"drive-{options.drive}"))
    if options.include_fixed_drives and not options.additional_roots:
        requests.extend(RootRequest(path, RootScope.FIXED_DRIVE, f"drive-{path}") for path in _fixed_drive_roots())
    if options.include_user_profile and not options.additional_roots:
        profile = _profile_root()
        if profile is not None:
            requests.append(RootRequest(_normalize_path(profile), RootScope.USER_PROFILE, "user-profile"))
    requests.extend(
        RootRequest(_normalize_path(path), RootScope.ADDITIONAL_LOCAL, "additional-local")
        for path in options.additional_roots
    )
    unique: dict[str, RootRequest] = {}
    for request in requests:
        unique.setdefault(os.path.normcase(request.path), request)
    return tuple(sorted(unique.values(), key=lambda item: (len(item.path), item.path.casefold(), item.path)))


def _gate(request: RootRequest, allow_network: bool) -> tuple[RootObservation, bool]:
    boundary = classify_root(request.path)
    if boundary in {RootBoundary.UNC, RootBoundary.NETWORK, RootBoundary.MAPPED_DRIVE} and not allow_network:
        return RootObservation(request.path, request.scope, request.label, boundary, RootStatus.DENIED, "network-backed roots are denied by default", request.artifact), False
    if boundary in {RootBoundary.REMOVABLE_DRIVE, RootBoundary.UNKNOWN}:
        return RootObservation(request.path, request.scope, request.label, boundary, RootStatus.DENIED, "only local fixed drives or explicit local directories are approved", request.artifact), False
    try:
        metadata = os.lstat(request.path)
    except FileNotFoundError:
        return RootObservation(request.path, request.scope, request.label, boundary, RootStatus.SKIPPED, "root was not found", request.artifact), False
    except PermissionError:
        return RootObservation(request.path, request.scope, request.label, boundary, RootStatus.FAILED, "root could not be read", request.artifact), False
    except OSError as error:
        return RootObservation(request.path, request.scope, request.label, boundary, RootStatus.FAILED, f"root observation failed: {type(error).__name__}", request.artifact), False
    if stat.S_ISLNK(metadata.st_mode):
        return RootObservation(request.path, request.scope, request.label, boundary, RootStatus.DENIED, "root is a symlink and was not followed", request.artifact), False
    if bool(getattr(metadata, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)):
        return RootObservation(request.path, request.scope, request.label, boundary, RootStatus.DENIED, "root is a reparse point and was not followed", request.artifact), False
    if not stat.S_ISDIR(metadata.st_mode):
        return RootObservation(request.path, request.scope, request.label, boundary, RootStatus.DENIED, "root is not an ordinary directory", request.artifact), False
    return RootObservation(request.path, request.scope, request.label, boundary, RootStatus.COMPLETE, "approved by the Scan Safety Gate", request.artifact), True


def scan_system(options: SystemScanOptions | None = None) -> SystemScan:
    """Discover approved local developer storage without mutation or network calls."""

    options = options or SystemScanOptions()
    workspace_requests = _requests(options)
    storage_requests = (
        options.global_storage_roots
        if options.global_storage_roots
        else approved_global_storage_roots()
        if options.include_global_storage
        else ()
    )
    all_requested = tuple(sorted(
        {request.path for request in workspace_requests + storage_requests},
        key=lambda item: (item.casefold(), item),
    ))
    budget = ScanBudget(limits=options.limits, cancellation=options.cancellation)
    root_observations: list[RootObservation] = []
    workspace_findings: list[Finding] = []
    global_findings: list[Finding] = []
    git_observations: list[GitContextObservation] = []
    failures: list[str] = []
    ambiguous: list[str] = []
    scanned_roots: list[str] = []

    for request in workspace_requests:
        if any(_same_or_within(request.path, scanned) for scanned in scanned_roots):
            boundary = classify_root(request.path)
            root_observations.append(RootObservation(request.path, request.scope, request.label, boundary, RootStatus.SKIPPED, "covered by an already approved root", request.artifact))
            continue
        if budget.stopped():
            boundary = classify_root(request.path)
            root_observations.append(RootObservation(request.path, request.scope, request.label, boundary, RootStatus.SKIPPED, f"scan stopped: {budget.termination.value}", request.artifact))
            continue
        gate_result, allowed = _gate(request, options.allow_network)
        if not allowed:
            root_observations.append(gate_result)
            continue
        try:
            result = scan_workspace(request.path, budget=budget)
        except (OSError, ValueError) as error:
            root_observations.append(RootObservation(request.path, request.scope, request.label, gate_result.boundary, RootStatus.FAILED, f"scan failed: {type(error).__name__}", request.artifact))
            failures.append(f"{request.path}: {type(error).__name__}")
            continue
        scanned_roots.append(request.path)
        root_failures = list(result.observation_failures)
        for finding in result.findings:
            root_failures.extend(_finding_observation_failures(finding))
        root_complete = result.termination is ScanTermination.COMPLETED and not root_failures
        root_observations.append(RootObservation(
            request.path,
            request.scope,
            request.label,
            gate_result.boundary,
            RootStatus.COMPLETE if root_complete else RootStatus.PARTIAL,
            "scan completed" if root_complete else (
                f"observation incomplete: {len(root_failures)} failure(s)"
                if result.termination is ScanTermination.COMPLETED
                else f"scan stopped: {result.termination.value}"
            ),
            request.artifact,
        ))
        workspace_findings.extend(result.findings)
        git_observations.extend(result.git_observations)
        failures.extend(root_failures)
        ambiguous.extend(result.ambiguous_paths)

    for request in storage_requests:
        if budget.stopped():
            boundary = classify_root(request.path)
            root_observations.append(RootObservation(request.path, request.scope, request.label, boundary, RootStatus.SKIPPED, f"scan stopped: {budget.termination.value}", request.artifact))
            continue
        gate_result, allowed = _gate(request, options.allow_network)
        if not allowed:
            root_observations.append(gate_result)
            continue
        detection = inspect_global_storage(request.path, request.artifact, approved_root=True, budget=budget)
        finding = evaluate_analysis(
            AnalysisResult(request.artifact, detection, interpret_global_storage(detection)),
            size=collect_size(request.path, budget=budget),
        )
        global_findings.append(finding)
        global_failures = _finding_observation_failures(finding)
        failures.extend(global_failures)
        global_complete = budget.termination is ScanTermination.COMPLETED and not global_failures
        root_observations.append(RootObservation(
            request.path,
            request.scope,
            request.label,
            gate_result.boundary,
            RootStatus.COMPLETE if global_complete else RootStatus.PARTIAL,
            "bounded global cache analysis completed" if global_complete else (
                f"global cache evidence incomplete: {len(global_failures)} failure(s)"
                if budget.termination is ScanTermination.COMPLETED
                else f"analysis stopped: {budget.termination.value}"
            ),
            request.artifact,
        ))

    workspace_findings.sort(key=lambda item: (item.path.casefold(), item.path, item.artifact.value))
    global_findings.sort(key=lambda item: (item.path.casefold(), item.path, item.artifact.value))
    git_observations.sort(key=lambda item: (item.node.path.casefold(), item.node.path))
    return SystemScan(
        requested_roots=all_requested,
        root_observations=tuple(sorted(root_observations, key=lambda item: (item.path.casefold(), item.path, item.scope.value, item.label))),
        workspace_findings=tuple(workspace_findings),
        global_storage_findings=tuple(global_findings),
        git_observations=tuple(git_observations),
        observation_failures=tuple(sorted(set(failures))),
        ambiguous_boundaries=tuple(sorted(ambiguous)),
        termination=budget.termination,
        nodes_observed=budget.nodes_observed,
        files_observed=budget.files_observed,
    )
