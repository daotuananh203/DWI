"""Stable machine-facing MCP vocabulary.

This module intentionally contains no engine capability or proof objects. Those
objects remain server-side values owned by :mod:`dwi.mcp.service`.
"""

from __future__ import annotations

from enum import Enum


class McpHandleType(str, Enum):
    SCAN = "scan"
    REVIEW = "review"
    EXECUTION = "execution"
    RECOVERY = "recovery"


class McpHandleState(str, Enum):
    ACTIVE = "ACTIVE"
    WAITING_FOR_HUMAN_CONFIRMATION = "WAITING_FOR_HUMAN_CONFIRMATION"
    READY_FOR_REVALIDATION = "READY_FOR_REVALIDATION"
    READY_FOR_EXECUTION = "READY_FOR_EXECUTION"
    EXECUTING = "EXECUTING"
    COMPLETE = "COMPLETE"
    CONSUMED = "CONSUMED"
    STALE = "STALE"
    RECONCILIATION_REQUIRED = "RECONCILIATION_REQUIRED"
    FAILED = "FAILED"


class McpErrorCode(str, Enum):
    INVALID_HANDLE = "INVALID_HANDLE"
    WRONG_HANDLE_TYPE = "WRONG_HANDLE_TYPE"
    STALE_HANDLE = "STALE_HANDLE"
    CONSUMED_HANDLE = "CONSUMED_HANDLE"
    HUMAN_CONFIRMATION_REQUIRED = "HUMAN_CONFIRMATION_REQUIRED"
    REVALIDATION_BLOCKED = "REVALIDATION_BLOCKED"
    RECONCILIATION_REQUIRED = "RECONCILIATION_REQUIRED"
    EXECUTION_FAILED = "EXECUTION_FAILED"
    PARTIAL_RESULT = "PARTIAL_RESULT"
    RECOVERY_NOT_FOUND = "RECOVERY_NOT_FOUND"
    INVALID_REQUEST = "INVALID_REQUEST"
    RESOURCE_LIMIT = "RESOURCE_LIMIT"
    INTERNAL_ERROR = "INTERNAL_ERROR"


class McpServiceError(Exception):
    """A deterministic, safe-to-return service error without a traceback."""

    def __init__(self, code: McpErrorCode, message: str, *, details: object | None = None) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.details = details

    def as_dict(self) -> dict[str, object]:
        result: dict[str, object] = {
            "code": self.code.value,
            "message": self.message,
        }
        if self.details is not None:
            result["details"] = self.details
        return result
