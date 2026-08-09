"""Versionable MCP tool schemas and strict argument validation."""

from __future__ import annotations

import math
from typing import Any

from ..scan_control import (
    DEFAULT_MAX_FILES,
    DEFAULT_MAX_NODES,
    DEFAULT_MAX_SECONDS,
    MAX_SCAN_FILES,
    MAX_SCAN_NODES,
    MAX_SCAN_ROOTS,
    MAX_SCAN_SECONDS,
)
from .models import McpErrorCode, McpServiceError


# MCP is an untrusted local boundary. These are both the normal defaults and
# the maximum caller-requestable budgets; callers may only request less.
MCP_DEFAULT_MAX_SECONDS = DEFAULT_MAX_SECONDS
MCP_DEFAULT_MAX_NODES = DEFAULT_MAX_NODES
MCP_DEFAULT_MAX_FILES = DEFAULT_MAX_FILES
MCP_MAX_SECONDS = MAX_SCAN_SECONDS
MCP_MAX_NODES = MAX_SCAN_NODES
MCP_MAX_FILES = MAX_SCAN_FILES
MCP_MAX_PAGE_SIZE = 100
MCP_DEFAULT_PAGE_SIZE = 50
MCP_MAX_FINDING_IDS = 256
MCP_MAX_ROOTS = MAX_SCAN_ROOTS


def _schema(properties: dict[str, object], required: tuple[str, ...] = ()) -> dict[str, object]:
    return {
        "type": "object",
        "properties": properties,
        "required": list(required),
        "additionalProperties": False,
    }


TOOL_DEFINITIONS: tuple[dict[str, object], ...] = (
    {
        "name": "dwi_scan_system",
        "description": "Read-only scan of approved DWI roots. Returns an opaque scan handle.",
        "inputSchema": _schema({
            "roots": {"type": "array", "maxItems": MCP_MAX_ROOTS, "items": {"type": "string"}},
            "allow_network": {"type": "boolean", "default": False},
            "max_seconds": {"type": "number", "exclusiveMinimum": 0, "maximum": MCP_MAX_SECONDS},
            "max_nodes": {"type": "integer", "minimum": 1, "maximum": MCP_MAX_NODES},
            "max_files": {"type": "integer", "minimum": 1, "maximum": MCP_MAX_FILES},
        }),
    },
    {
        "name": "dwi_scan_root",
        "description": "Read-only scan of one explicitly supplied root; raw paths are never mutation targets.",
        "inputSchema": _schema({
            "root": {"type": "string"},
            "allow_network": {"type": "boolean", "default": False},
            "max_seconds": {"type": "number", "exclusiveMinimum": 0, "maximum": MCP_MAX_SECONDS},
            "max_nodes": {"type": "integer", "minimum": 1, "maximum": MCP_MAX_NODES},
            "max_files": {"type": "integer", "minimum": 1, "maximum": MCP_MAX_FILES},
        }, ("root",)),
    },
    {
        "name": "dwi_get_scan_summary",
        "description": "Read a summary from a server-owned scan handle.",
        "inputSchema": _schema({
            "scan_handle": {"type": "string"},
            "limit": {"type": "integer", "minimum": 1, "maximum": MCP_MAX_PAGE_SIZE},
            "cursor": {"type": "string"},
        }, ("scan_handle",)),
    },
    {
        "name": "dwi_list_findings",
        "description": "List engine-generated findings from a server-owned scan handle.",
        "inputSchema": _schema({
            "scan_handle": {"type": "string"},
            "limit": {"type": "integer", "minimum": 1, "maximum": MCP_MAX_PAGE_SIZE},
            "cursor": {"type": "string"},
        }, ("scan_handle",)),
    },
    {
        "name": "dwi_get_finding",
        "description": "Read one engine-generated finding by scan handle and finding ID.",
        "inputSchema": _schema({
            "scan_handle": {"type": "string"},
            "finding_id": {"type": "string"},
        }, ("scan_handle", "finding_id")),
    },
    {
        "name": "dwi_explain_finding",
        "description": "Return deterministic evidence and rule-trace explanation for a finding.",
        "inputSchema": _schema({
            "scan_handle": {"type": "string"},
            "finding_id": {"type": "string"},
        }, ("scan_handle", "finding_id")),
    },
    {
        "name": "dwi_create_cleanup_review",
        "description": "Create an engine-bound cleanup review from finding IDs only. No raw path or safety fields are accepted.",
        "inputSchema": _schema({
            "scan_handle": {"type": "string"},
            "finding_ids": {"type": "array", "minItems": 1, "maxItems": MCP_MAX_FINDING_IDS, "items": {"type": "string"}},
        }, ("scan_handle", "finding_ids")),
    },
    {
        "name": "dwi_get_cleanup_review",
        "description": "Read a server-owned cleanup review. Agent confirmation is not available through MCP.",
        "inputSchema": _schema({
            "review_handle": {"type": "string"},
            "limit": {"type": "integer", "minimum": 1, "maximum": MCP_MAX_PAGE_SIZE},
            "cursor": {"type": "string"},
        }, ("review_handle",)),
    },
    {
        "name": "dwi_request_cleanup_execution",
        "description": "Request an execution handle after trusted human confirmation; does not accept confirmation text.",
        "inputSchema": _schema({"review_handle": {"type": "string"}}, ("review_handle",)),
    },
    {
        "name": "dwi_execute_cleanup",
        "description": "Execute exactly one server-owned, human-confirmed workflow using fresh engine revalidation.",
        "inputSchema": _schema({"execution_handle": {"type": "string"}}, ("execution_handle",)),
    },
    {
        "name": "dwi_get_execution_status",
        "description": "Read status and per-item reality for a server-owned execution handle.",
        "inputSchema": _schema({
            "execution_handle": {"type": "string"},
            "limit": {"type": "integer", "minimum": 1, "maximum": MCP_MAX_PAGE_SIZE},
            "cursor": {"type": "string"},
        }, ("execution_handle",)),
    },
    {
        "name": "dwi_get_recovery_status",
        "description": "List validated recovery handles and recovery state for one execution.",
        "inputSchema": _schema({
            "execution_handle": {"type": "string"},
            "limit": {"type": "integer", "minimum": 1, "maximum": MCP_MAX_PAGE_SIZE},
            "cursor": {"type": "string"},
        }, ("execution_handle",)),
    },
    {
        "name": "dwi_request_undo",
        "description": "Restore one server-owned recovery handle through journal validation; no destination path is accepted.",
        "inputSchema": _schema({"recovery_handle": {"type": "string"}}, ("recovery_handle",)),
    },
)


_SCHEMAS_BY_NAME = {str(tool["name"]): tool["inputSchema"] for tool in TOOL_DEFINITIONS}

_SCAN_BUDGET_SCHEMAS = {
    "max_seconds": {"type": "number", "exclusiveMinimum": 0, "maximum": MCP_MAX_SECONDS},
    "max_nodes": {"type": "integer", "minimum": 1, "maximum": MCP_MAX_NODES},
    "max_files": {"type": "integer", "minimum": 1, "maximum": MCP_MAX_FILES},
}


def _is_number(value: object) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _validate_value(name: str, value: object, schema: dict[str, object]) -> None:
    schema_type = schema.get("type")
    if schema_type == "string" and not isinstance(value, str):
        raise McpServiceError(McpErrorCode.INVALID_REQUEST, f"{name} must be a string")
    if schema_type == "boolean" and not isinstance(value, bool):
        raise McpServiceError(McpErrorCode.INVALID_REQUEST, f"{name} must be a boolean")
    if schema_type == "number" and not _is_number(value):
        raise McpServiceError(McpErrorCode.INVALID_REQUEST, f"{name} must be a number")
    if schema_type == "integer" and (not isinstance(value, int) or isinstance(value, bool)):
        raise McpServiceError(McpErrorCode.INVALID_REQUEST, f"{name} must be an integer")
    if schema_type == "array":
        if not isinstance(value, list):
            raise McpServiceError(McpErrorCode.INVALID_REQUEST, f"{name} must be an array")
        minimum = schema.get("minItems")
        maximum = schema.get("maxItems")
        if isinstance(minimum, int) and len(value) < minimum:
            raise McpServiceError(McpErrorCode.INVALID_REQUEST, f"{name} must not be empty")
        if isinstance(maximum, int) and len(value) > maximum:
            raise McpServiceError(McpErrorCode.RESOURCE_LIMIT, f"{name} exceeds its maximum item count")
        item_schema = schema.get("items")
        if isinstance(item_schema, dict):
            for index, item in enumerate(value):
                _validate_value(f"{name}[{index}]", item, item_schema)
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if isinstance(value, float) and not math.isfinite(value):
            raise McpServiceError(McpErrorCode.INVALID_REQUEST, f"{name} must be finite")
        minimum = schema.get("minimum")
        exclusive_minimum = schema.get("exclusiveMinimum")
        maximum = schema.get("maximum")
        if isinstance(minimum, (int, float)) and value < minimum:
            raise McpServiceError(McpErrorCode.INVALID_REQUEST, f"{name} is below its minimum")
        if isinstance(exclusive_minimum, (int, float)) and value <= exclusive_minimum:
            raise McpServiceError(McpErrorCode.INVALID_REQUEST, f"{name} must be greater than zero")
        if isinstance(maximum, (int, float)) and value > maximum:
            raise McpServiceError(McpErrorCode.INVALID_REQUEST, f"{name} exceeds its hard maximum")


def validate_scan_budget(
    *,
    max_seconds: object,
    max_nodes: object,
    max_files: object,
) -> None:
    """Validate scan limits for both protocol calls and direct service use."""

    for name, value in (
        ("max_seconds", max_seconds),
        ("max_nodes", max_nodes),
        ("max_files", max_files),
    ):
        schema = _SCAN_BUDGET_SCHEMAS[name]
        _validate_value(name, value, schema)


def validate_arguments(tool_name: str, arguments: object) -> dict[str, Any]:
    schema = _SCHEMAS_BY_NAME.get(tool_name)
    if schema is None:
        raise McpServiceError(McpErrorCode.INVALID_REQUEST, f"unknown MCP tool: {tool_name}")
    if not isinstance(arguments, dict):
        raise McpServiceError(McpErrorCode.INVALID_REQUEST, "tool arguments must be an object")
    properties = schema.get("properties", {})
    required = schema.get("required", [])
    if not isinstance(properties, dict) or not isinstance(required, list):
        raise McpServiceError(McpErrorCode.INTERNAL_ERROR, "MCP schema is invalid")
    unknown = sorted(set(arguments) - set(properties))
    if unknown:
        raise McpServiceError(McpErrorCode.INVALID_REQUEST, f"unexpected tool argument: {unknown[0]}")
    missing = [name for name in required if name not in arguments]
    if missing:
        raise McpServiceError(McpErrorCode.INVALID_REQUEST, f"missing tool argument: {missing[0]}")
    for name, value in arguments.items():
        schema_value = properties.get(name)
        if isinstance(schema_value, dict):
            _validate_value(name, value, schema_value)
    return dict(arguments)
