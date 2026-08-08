"""Deterministic, read-only bounded size accounting."""

from __future__ import annotations

import os
import stat
from dataclasses import dataclass
from pathlib import Path


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


def collect_size(path: str | os.PathLike[str]) -> SizeObservation:
    """Sum regular files below one path without following links or reparse points."""
    root = Path(path)
    total = 0
    failures: list[str] = []
    skipped: list[str] = []
    seen: set[tuple[int, int]] = set()
    stack = [root]
    while stack:
        current = stack.pop()
        try:
            metadata = os.lstat(current)
        except (OSError, ValueError) as error:
            failures.append(f"{current}: {type(error).__name__}")
            continue
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
            for child in reversed(children):
                stack.append(Path(child.path))
        except (OSError, ValueError) as error:
            failures.append(f"{current}: {type(error).__name__}")
    return SizeObservation(total, not failures and not skipped, tuple(sorted(failures)), tuple(sorted(skipped)))
