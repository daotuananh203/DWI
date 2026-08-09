"""Bounded in-memory opaque handle registry for the untrusted MCP boundary."""

from __future__ import annotations

import math
import secrets
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass

from .models import McpErrorCode, McpHandleState, McpHandleType, McpServiceError


@dataclass
class _HandleEntry:
    handle: str
    handle_type: McpHandleType
    payload: object
    state: McpHandleState
    created_at: float
    expires_at: float
    consumed: bool = False


@dataclass(frozen=True)
class _StaleTombstone:
    handle_type: McpHandleType
    expires_at: float


class OpaqueHandleStore:
    """Server-owned bounded registry for opaque, non-persistent handles.

    Live entries retain authoritative payloads only until their TTL. Expiration
    removes the entry and payload from the live store; a bounded, payload-free
    tombstone may remain briefly so a caller receives ``STALE_HANDLE`` instead
    of an indistinguishable invalid-handle response. Active entries are never
    silently evicted when capacity is exhausted.
    """

    DEFAULT_MAX_ENTRIES = 256

    def __init__(
        self,
        *,
        ttl_seconds: float = 900.0,
        max_entries: int = DEFAULT_MAX_ENTRIES,
        clock=time.monotonic,
    ) -> None:
        if isinstance(ttl_seconds, bool) or not isinstance(ttl_seconds, (int, float)):
            raise ValueError("MCP handle TTL must be a finite number")
        if isinstance(ttl_seconds, float) and not math.isfinite(ttl_seconds):
            raise ValueError("MCP handle TTL must be a finite number")
        if ttl_seconds <= 0:
            raise ValueError("MCP handle TTL must be positive")
        if isinstance(max_entries, bool) or not isinstance(max_entries, int) or max_entries <= 0:
            raise ValueError("MCP handle capacity must be a positive integer")
        self._ttl_seconds = float(ttl_seconds)
        self._max_entries = max_entries
        self._clock = clock
        self._lock = threading.RLock()
        self._entries: dict[str, _HandleEntry] = {}
        self._tombstones: OrderedDict[str, _StaleTombstone] = OrderedDict()

    @property
    def max_entries(self) -> int:
        return self._max_entries

    @property
    def live_entry_count(self) -> int:
        with self._lock:
            self._purge_expired_locked(self._clock())
            return len(self._entries)

    @property
    def tombstone_count(self) -> int:
        with self._lock:
            self._purge_tombstones_locked(self._clock())
            return len(self._tombstones)

    def _purge_tombstones_locked(self, now: float) -> None:
        expired = [handle for handle, tombstone in self._tombstones.items() if now >= tombstone.expires_at]
        for handle in expired:
            self._tombstones.pop(handle, None)

    def _remember_stale_locked(self, entry: _HandleEntry, now: float) -> None:
        # The tombstone contains only a type and bounded retention timestamp.
        self._tombstones.pop(entry.handle, None)
        self._tombstones[entry.handle] = _StaleTombstone(entry.handle_type, now + self._ttl_seconds)
        while len(self._tombstones) > self._max_entries:
            self._tombstones.popitem(last=False)

    def _purge_expired_locked(self, now: float) -> None:
        self._purge_tombstones_locked(now)
        expired = [handle for handle, entry in self._entries.items() if now >= entry.expires_at]
        for handle in expired:
            entry = self._entries.pop(handle)
            # Dropping the dict entry drops the authoritative payload. Do not
            # retain the entry object in a tombstone or exception details.
            self._remember_stale_locked(entry, now)

    def issue(
        self,
        handle_type: McpHandleType,
        payload: object,
        *,
        state: McpHandleState = McpHandleState.ACTIVE,
    ) -> str:
        with self._lock:
            now = self._clock()
            self._purge_expired_locked(now)
            if len(self._entries) >= self._max_entries:
                raise McpServiceError(
                    McpErrorCode.RESOURCE_LIMIT,
                    "MCP handle capacity is exhausted; active authority was not evicted",
                )
            while True:
                handle = f"{handle_type.value}_{secrets.token_urlsafe(32)}"
                if handle not in self._entries and handle not in self._tombstones:
                    break
            self._entries[handle] = _HandleEntry(
                handle,
                handle_type,
                payload,
                state,
                now,
                now + self._ttl_seconds,
            )
            return handle

    @staticmethod
    def _validate_handle_text(handle: object) -> str:
        if not isinstance(handle, str) or not handle.strip():
            raise McpServiceError(McpErrorCode.INVALID_HANDLE, "handle must be a non-empty opaque string")
        return handle

    def _resolve_locked(
        self,
        handle: object,
        expected: McpHandleType,
        *,
        allow_consumed: bool,
    ) -> _HandleEntry:
        handle_text = self._validate_handle_text(handle)
        self._purge_expired_locked(self._clock())
        entry = self._entries.get(handle_text)
        if entry is not None:
            if entry.handle_type is not expected:
                raise McpServiceError(
                    McpErrorCode.WRONG_HANDLE_TYPE,
                    f"handle is not a {expected.value} handle",
                )
            if entry.consumed and not allow_consumed:
                raise McpServiceError(McpErrorCode.CONSUMED_HANDLE, "one-shot handle was already consumed")
            return entry
        tombstone = self._tombstones.get(handle_text)
        if tombstone is not None:
            if tombstone.handle_type is not expected:
                raise McpServiceError(
                    McpErrorCode.WRONG_HANDLE_TYPE,
                    f"handle is not a {expected.value} handle",
                )
            raise McpServiceError(McpErrorCode.STALE_HANDLE, "handle expired and authority was reclaimed")
        raise McpServiceError(McpErrorCode.INVALID_HANDLE, "handle was not issued by this MCP service")

    def resolve(
        self,
        handle: object,
        expected: McpHandleType,
        *,
        allow_consumed: bool = False,
    ) -> _HandleEntry:
        with self._lock:
            return self._resolve_locked(handle, expected, allow_consumed=allow_consumed)

    def transition(self, handle: object, expected: McpHandleType, state: McpHandleState) -> None:
        with self._lock:
            entry = self._resolve_locked(handle, expected, allow_consumed=False)
            entry.state = state

    def consume(self, handle: object, expected: McpHandleType) -> object:
        """Atomically mark a one-shot handle consumed before doing work."""

        with self._lock:
            entry = self._resolve_locked(handle, expected, allow_consumed=False)
            entry.consumed = True
            entry.state = McpHandleState.EXECUTING
            return entry.payload

    def complete(self, handle: object, expected: McpHandleType, state: McpHandleState) -> None:
        with self._lock:
            self._purge_expired_locked(self._clock())
            entry = self._entries.get(handle) if isinstance(handle, str) else None
            if entry is None or entry.handle_type is not expected:
                return
            entry.state = state

    def state(self, handle: object, expected: McpHandleType, *, allow_consumed: bool = False) -> McpHandleState:
        return self.resolve(handle, expected, allow_consumed=allow_consumed).state
