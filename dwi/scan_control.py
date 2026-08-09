"""Deterministic controls shared by bounded read-only scans."""

from __future__ import annotations

import time
import math
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable


# Shared conservative resource gate. Every public adapter may reduce these
# values but must not expand them without a future safety review.
DEFAULT_MAX_SECONDS = 300.0
DEFAULT_MAX_NODES = 100_000
DEFAULT_MAX_FILES = 100_000
MAX_SCAN_SECONDS = DEFAULT_MAX_SECONDS
MAX_SCAN_NODES = DEFAULT_MAX_NODES
MAX_SCAN_FILES = DEFAULT_MAX_FILES
MAX_SCAN_ROOTS = 32


class ScanTermination(str, Enum):
    COMPLETED = "completed"
    CANCELLED = "cancelled"
    TIME_LIMIT = "time_limit"
    NODE_LIMIT = "node_limit"
    FILE_LIMIT = "file_limit"


@dataclass(frozen=True)
class ScanLimits:
    """Finite bounds for one read-only scan.

    ``None`` is accepted for compatibility with older adapters but is
    normalized to the shared conservative default; no public scan becomes
    unlimited by omission.
    """

    max_seconds: float | None = DEFAULT_MAX_SECONDS
    max_nodes: int | None = DEFAULT_MAX_NODES
    max_files: int | None = DEFAULT_MAX_FILES

    def __post_init__(self) -> None:
        numeric = (
            ("max_seconds", self.max_seconds, (int, float), MAX_SCAN_SECONDS, DEFAULT_MAX_SECONDS),
            ("max_nodes", self.max_nodes, (int,), MAX_SCAN_NODES, DEFAULT_MAX_NODES),
            ("max_files", self.max_files, (int,), MAX_SCAN_FILES, DEFAULT_MAX_FILES),
        )
        for name, value, accepted_types, maximum, fallback in numeric:
            if value is None:
                object.__setattr__(self, name, fallback)
                value = fallback
            if isinstance(value, bool) or not isinstance(value, accepted_types):
                raise ValueError(f"{name} has an invalid numeric type")
            if isinstance(value, float) and not math.isfinite(value):
                raise ValueError(f"{name} must be finite")
            if value < 0:
                raise ValueError(f"{name} must not be negative")
            if value > maximum:
                raise ValueError(f"{name} exceeds its hard maximum of {maximum}")


@dataclass
class ScanBudget:
    """Mutable internal accounting for a scan that may span several roots."""

    limits: ScanLimits = field(default_factory=ScanLimits)
    cancellation: Callable[[], bool] | None = None
    started_at: float = field(default_factory=time.monotonic)
    nodes_observed: int = 0
    files_observed: int = 0
    termination: ScanTermination = ScanTermination.COMPLETED

    def poll(self) -> bool:
        if self.termination is not ScanTermination.COMPLETED:
            return False
        if self.cancellation is not None and self.cancellation():
            self.termination = ScanTermination.CANCELLED
            return False
        if (
            self.limits.max_seconds is not None
            and time.monotonic() - self.started_at >= self.limits.max_seconds
        ):
            self.termination = ScanTermination.TIME_LIMIT
            return False
        return True

    def observe_node(self, *, is_file: bool = False) -> bool:
        if not self.poll():
            return False
        if self.limits.max_nodes is not None and self.nodes_observed >= self.limits.max_nodes:
            self.termination = ScanTermination.NODE_LIMIT
            return False
        if is_file and self.limits.max_files is not None and self.files_observed >= self.limits.max_files:
            self.termination = ScanTermination.FILE_LIMIT
            return False
        self.nodes_observed += 1
        if is_file:
            self.files_observed += 1
        return True

    def stopped(self) -> bool:
        self.poll()
        return self.termination is not ScanTermination.COMPLETED
