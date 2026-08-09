"""Bounded, read-only pagination helpers for MCP list results."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Sequence, TypeVar

from .models import McpErrorCode, McpServiceError


T = TypeVar("T")


@dataclass(frozen=True)
class Page:
    items: tuple[object, ...]
    next_cursor: str | None
    total: int
    limit: int
    start: int


def _fingerprint(key: str, total: int) -> str:
    return hashlib.sha256(f"{key}\x00{total}".encode("utf-8")).hexdigest()[:24]


def page_items(
    items: Sequence[T],
    *,
    key: str,
    limit: int,
    cursor: object = None,
    maximum: int,
) -> Page:
    """Return one bounded page; the cursor carries no mutation authority."""

    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= maximum:
        raise McpServiceError(McpErrorCode.INVALID_REQUEST, "page limit is outside the allowed range")
    total = len(items)
    digest = _fingerprint(key, total)
    start = 0
    if cursor is not None:
        if not isinstance(cursor, str) or not cursor:
            raise McpServiceError(McpErrorCode.INVALID_REQUEST, "page cursor must be a non-empty string")
        try:
            prefix, cursor_digest = cursor.rsplit("_", 1)
            start = int(prefix)
        except (ValueError, TypeError) as error:
            raise McpServiceError(McpErrorCode.INVALID_REQUEST, "page cursor is malformed") from error
        if cursor_digest != digest or start < 0 or start > total:
            raise McpServiceError(McpErrorCode.INVALID_REQUEST, "page cursor is stale or invalid")
    end = min(start + limit, total)
    next_cursor = f"{end}_{digest}" if end < total else None
    return Page(tuple(items[start:end]), next_cursor, total, limit, start)
