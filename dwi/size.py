"""Deterministic, read-only bounded size accounting."""

from __future__ import annotations

import os
import stat
from dataclasses import dataclass
from pathlib import Path

from .scan_control import ScanBudget


@dataclass(frozen=True)
class SizeObservation:
    known_bytes: int
    complete: bool
    observation_failures: tuple[str, ...] = ()
    links_skipped: tuple[str, ...] = ()

    @classmethod
    def unknown(cls) -> "SizeObservation":
        return cls(0, False, ("size-not-collected",))


def _reparse(st: os.stat_result) -> bool:
    return bool(getattr(st, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))


def _metadata_identity(metadata: os.stat_result) -> tuple[int, int, int, bool]:
    return (
        getattr(metadata, "st_dev", 0),
        getattr(metadata, "st_ino", 0),
        stat.S_IFMT(metadata.st_mode),
        _reparse(metadata),
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


def collect_size(
    path: str | os.PathLike[str],
    *,
    budget: ScanBudget | None = None,
) -> SizeObservation:
    """Sum regular files below one path without following links or reparse points."""
    root = Path(path)
    total = 0
    failures: list[str] = []
    skipped: list[str] = []
    seen: set[tuple[int, int]] = set()
    stack = [root]
    while stack:
        if budget is not None and budget.stopped():
            break
        current = stack.pop()
        try:
            metadata = os.lstat(current)
        except (OSError, ValueError) as error:
            failures.append(f"{current}: {type(error).__name__}")
            continue
        if not _within_root(root, current):
            failures.append(f"{current}: outside-approved-root")
            continue
        try:
            stable_metadata = os.lstat(current)
        except (OSError, ValueError) as error:
            failures.append(f"{current}: {type(error).__name__}")
            continue
        if not _metadata_matches(metadata, stable_metadata):
            failures.append(f"{current}: traversal-race")
            continue
        metadata = stable_metadata
        if budget is not None and not budget.observe_node(is_file=stat.S_ISREG(metadata.st_mode)):
            break
        if stat.S_ISLNK(metadata.st_mode) or _reparse(metadata):
            skipped.append(str(current))
            continue
        if stat.S_ISREG(metadata.st_mode):
            total += metadata.st_size
            continue
        if not stat.S_ISDIR(metadata.st_mode):
            failures.append(f"{current}: unsupported-node")
            continue
        identity = (getattr(metadata, "st_dev", 0), getattr(metadata, "st_ino", 0))
        if identity in seen:
            failures.append(f"{current}: repeated-directory")
            continue
        seen.add(identity)
        try:
            children = sorted(os.scandir(current), key=lambda item: (item.name.casefold(), item.name))
            after_scan = os.lstat(current)
            if not _metadata_matches(metadata, after_scan):
                failures.append(f"{current}: traversal-race")
                continue
            for child in reversed(children):
                stack.append(Path(child.path))
        except (OSError, ValueError) as error:
            failures.append(f"{current}: {type(error).__name__}")
    if budget is not None and budget.termination.value != "completed":
        failures.append(f"scan-limit:{budget.termination.value}")
    return SizeObservation(total, not failures and not skipped, tuple(sorted(failures)), tuple(sorted(skipped)))
