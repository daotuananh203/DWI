"""Minimal local MCP JSON-RPC server over stdin/stdout."""

from __future__ import annotations

import json
import sys
from typing import TextIO

from .models import McpErrorCode, McpServiceError
from .service import McpService


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

    def handle_message(self, message: object) -> dict[str, object] | None:
        if not isinstance(message, dict) or message.get("jsonrpc") != "2.0":
            return {"jsonrpc": "2.0", "id": None, "error": {"code": -32600, "message": "Invalid Request"}}
        request_id = message.get("id")
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
                    "serverInfo": {"name": "dwi-mcp", "version": "0.5.0"},
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

    def serve_stdio(self, input_stream: TextIO | None = None, output_stream: TextIO | None = None) -> int:
        input_stream = input_stream or sys.stdin
        output_stream = output_stream or sys.stdout
        for line in input_stream:
            if not line.strip():
                continue
            try:
                message = json.loads(line)
                response = self.handle_message(message)
            except json.JSONDecodeError:
                response = {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "Parse error"}}
            if response is not None:
                output_stream.write(json.dumps(response, ensure_ascii=False, sort_keys=True) + "\n")
                output_stream.flush()
        return 0


def serve_stdio() -> int:
    return McpServer().serve_stdio()
