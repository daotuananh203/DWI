"""Developer-only, read-only real-machine evaluation harness."""

from __future__ import annotations

import platform
import sys
import time
from dataclasses import asdict, dataclass
from pathlib import Path

from .scan_control import ScanLimits
from .system_scan import RootStatus, SystemScanOptions, scan_system
from .version import __version__


@dataclass(frozen=True)
class ReadonlyEvaluation:
    version: str
    python: str
    platform: str
    network_allowed: bool
    requested_root: bool
    duration_ms: float
    termination: str
    nodes_observed: int
    files_observed: int
    findings_count: int
    known_analyzed_bytes: int
    potentially_reclaimable_bytes: int
    root_status_counts: dict[str, int]
    observation_failure_count: int
    ambiguous_boundary_count: int
    denied_network_boundary_count: int
    read_only: bool = True
    mutation_started: bool = False

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def run_readonly_evaluation(
    *,
    root: str | None = None,
    limits: ScanLimits | None = None,
    allow_network: bool = False,
) -> ReadonlyEvaluation:
    """Scan the current machine or one explicit root without mutation.

    The result intentionally contains counts and status categories only; it
    does not persist or export personal paths or finding contents.
    """

    options = SystemScanOptions(
        additional_roots=(str(Path(root)),) if root else (),
        include_fixed_drives=not bool(root),
        include_user_profile=not bool(root),
        include_global_storage=not bool(root),
        allow_network=allow_network,
        limits=limits or SystemScanOptions().limits,
    )
    started = time.perf_counter()
    scan = scan_system(options)
    duration_ms = round((time.perf_counter() - started) * 1000.0, 3)
    counts = {status.value: 0 for status in RootStatus}
    for observation in scan.root_observations:
        counts[observation.status.value] += 1
    return ReadonlyEvaluation(
        version=__version__,
        python=sys.version.split()[0],
        platform=f"{platform.system()} {platform.release()}",
        network_allowed=allow_network,
        requested_root=root is not None,
        duration_ms=duration_ms,
        termination=scan.termination.value,
        nodes_observed=scan.nodes_observed,
        files_observed=scan.files_observed,
        findings_count=len(scan.findings),
        known_analyzed_bytes=scan.summary.known_analyzed_bytes,
        potentially_reclaimable_bytes=scan.summary.potentially_reclaimable_bytes,
        root_status_counts=counts,
        observation_failure_count=len(scan.observation_failures),
        ambiguous_boundary_count=len(scan.ambiguous_boundaries),
        denied_network_boundary_count=len(scan.denied_network_boundaries),
    )
