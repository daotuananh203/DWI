"""Deterministic controls shared by bounded read-only scans."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable


class ScanTermination(str, Enum):
    COMPLETED = "completed"
    CANCELLED = "cancelled"
    TIME_LIMIT = "time_limit"
    NODE_LIMIT = "node_limit"
    FILE_LIMIT = "file_limit"


@dataclass(frozen=True)
class ScanLimits:
    """Optional bounds for one read-only scan."""

    max_seconds: float | None = None
    max_nodes: int | None = None
    max_files: int | None = None

    def __post_init__(self) -> None:
        for name, value in (
            ("max_seconds", self.max_seconds),
            ("max_nodes", self.max_nodes),
            ("max_files", self.max_files),
        ):
            if value is not None and value < 0:
                raise ValueError(f"{name} must not be negative")


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
