"""Minimal local MCP JSON-RPC server over bounded stdin/stdout messages."""

from __future__ import annotations

import json
import math
import sys
from typing import TextIO

from ..version import __version__
from .models import McpErrorCode, McpServiceError
from .service import McpService


# A line-oriented local transport still needs explicit resource limits. The
# limits are intentionally conservative and independent of scan budgets.
MCP_MAX_REQUEST_BYTES = 1_048_576
MCP_MAX_RESPONSE_BYTES = 1_048_576
_MAX_READ_CHARS = MCP_MAX_REQUEST_BYTES + 2


def _json_bytes(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def _reject_nonfinite_constant(value: str) -> object:
    raise ValueError(f"non-finite JSON constant is not permitted: {value}")


class McpServer:
    """MCP tools/list and tools/call adapter with no network listener."""

    def __init__(self, service: McpService | None = None) -> None:
        self.service = service or McpService()

    def _error_result(self, error: McpServiceError) -> dict[str, object]:
        payload = {"status": "ERROR", "error": error.as_dict()}
        return {
            "content": [{"type": "text", "text": json.dumps(payload, ensure_ascii=False, sort_keys=True)}],
            "structuredContent": payload,
            "isError": True,
        }

    def _handle_message(self, message: object) -> dict[str, object] | None:
        if not isinstance(message, dict) or message.get("jsonrpc") != "2.0":
            return {"jsonrpc": "2.0", "id": None, "error": {"code": -32600, "message": "Invalid Request"}}
        request_id = message.get("id")
        if request_id is not None and (
            isinstance(request_id, bool)
            or not isinstance(request_id, (str, int, float))
            or (isinstance(request_id, float) and not math.isfinite(request_id))
        ):
            return {"jsonrpc": "2.0", "id": None, "error": {"code": -32600, "message": "JSON-RPC id must be finite"}}
        method = message.get("method")
        if not isinstance(method, str):
            return {"jsonrpc": "2.0", "id": request_id, "error": {"code": -32600, "message": "Invalid Request"}}
        if method == "notifications/initialized":
            return None
        if method == "initialize":
            return {
                "jsonrpc": "2.0",
                "id": request_id,
                "result": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": "dwi-mcp", "version": __version__},
                },
            }
        if method == "tools/list":
            return {"jsonrpc": "2.0", "id": request_id, "result": {"tools": list(self.service.tool_definitions)}}
        if method == "tools/call":
            params = message.get("params")
            if not isinstance(params, dict) or not isinstance(params.get("name"), str):
                error = McpServiceError(McpErrorCode.INVALID_REQUEST, "tools/call requires a tool name")
                result = self._error_result(error)
            else:
                try:
                    output = self.service.call_tool(params["name"], params.get("arguments", {}))
                    result = {
                        "content": [{"type": "text", "text": json.dumps(output, ensure_ascii=False, sort_keys=True)}],
                        "structuredContent": output,
                        "isError": False,
                    }
                except McpServiceError as error:
                    result = self._error_result(error)
                except Exception:
                    result = self._error_result(McpServiceError(McpErrorCode.INTERNAL_ERROR, "MCP request failed at the service boundary"))
            return {"jsonrpc": "2.0", "id": request_id, "result": result}
        return {"jsonrpc": "2.0", "id": request_id, "error": {"code": -32601, "message": "Method not found"}}

    def _response_size_guard(self, response: dict[str, object] | None) -> dict[str, object] | None:
        if response is None:
            return None
        if len(_json_bytes(response)) <= MCP_MAX_RESPONSE_BYTES:
            return response
        return {
            "jsonrpc": "2.0",
            "id": response.get("id"),
            "error": {
                "code": -32002,
                "message": "MCP response exceeds the maximum message size",
                "data": {
                    "code": McpErrorCode.RESOURCE_LIMIT.value,
                    "max_bytes": MCP_MAX_RESPONSE_BYTES,
                },
            },
        }

    def handle_message(self, message: object) -> dict[str, object] | None:
        return self._response_size_guard(self._handle_message(message))

    @staticmethod
    def _read_line_bounded(input_stream: TextIO) -> tuple[str | None, bool]:
        line = input_stream.readline(_MAX_READ_CHARS)
        if not line:
            return None, False
        payload = line.split("\n", 1)[0].rstrip("\r")
        oversized = len(payload.encode("utf-8", errors="replace")) > MCP_MAX_REQUEST_BYTES
        if "\n" not in line and len(line) >= _MAX_READ_CHARS:
            oversized = True
        if oversized:
            # The bounded initial read stops before an attacker-controlled line
            # can consume the following request. Drain the remainder in bounded
            # chunks so a huge line never becomes one unbounded Python string.
            if "\n" not in line:
                while True:
                    remainder = input_stream.readline(8192)
                    if not remainder or "\n" in remainder:
                        break
        return (None if oversized else payload), oversized

    def serve_stdio(self, input_stream: TextIO | None = None, output_stream: TextIO | None = None) -> int:
        input_stream = input_stream or sys.stdin
        output_stream = output_stream or sys.stdout
        while True:
            line, oversized = self._read_line_bounded(input_stream)
            if line is None and not oversized:
                break
            if oversized:
                response: dict[str, object] | None = {
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {
                        "code": -32001,
                        "message": "MCP request exceeds the maximum message size",
                        "data": {
                            "code": McpErrorCode.RESOURCE_LIMIT.value,
                            "max_bytes": MCP_MAX_REQUEST_BYTES,
                        },
                    },
                }
            elif not line or not line.strip():
                continue
            else:
                try:
                    response = self.handle_message(json.loads(line, parse_constant=_reject_nonfinite_constant))
                except (json.JSONDecodeError, ValueError):
                    response = {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "Parse error"}}
            if response is not None:
                encoded = _json_bytes(response)
                # The guard above should make this branch unreachable for
                # ordinary responses; keep a final bounded fallback at the
                # transport write boundary.
                if len(encoded) > MCP_MAX_RESPONSE_BYTES:
                    encoded = _json_bytes({
                        "jsonrpc": "2.0",
                        "id": None,
                        "error": {
                            "code": -32002,
                            "message": "MCP response exceeds the maximum message size",
                            "data": {"code": McpErrorCode.RESOURCE_LIMIT.value, "max_bytes": MCP_MAX_RESPONSE_BYTES},
                        },
                    })
                output_stream.write(encoded.decode("utf-8") + "\n")
                output_stream.flush()
        return 0


def serve_stdio() -> int:
    return McpServer().serve_stdio()
