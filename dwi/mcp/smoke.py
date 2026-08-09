"""Safe developer smoke path for the local MCP adapter."""

from __future__ import annotations

import tempfile
from dataclasses import dataclass
from pathlib import Path

from .models import McpErrorCode
from .server import McpServer
from .service import McpService


@dataclass(frozen=True)
class McpSmokeResult:
    imported: bool
    initialized: bool
    tools_listed: bool
    scanned: bool
    findings_inspected: bool
    human_confirmation_guarded: bool
    mutation_executed: bool
    note: str


def _call(server: McpServer, request_id: int, name: str, arguments: dict[str, object]) -> dict[str, object]:
    response = server.handle_message({
        "jsonrpc": "2.0",
        "id": request_id,
        "method": "tools/call",
        "params": {"name": name, "arguments": arguments},
    })
    assert response is not None
    return response["result"]


def run_mcp_smoke() -> McpSmokeResult:
    """Scan only a disposable fixture and never supply human confirmation."""

    with tempfile.TemporaryDirectory(prefix="dwi-mcp-smoke-") as temporary:
        root = Path(temporary)
        cache = root / ".pytest_cache"
        cache.mkdir()
        (cache / "CACHEDIR.TAG").write_text(
            "Signature: 8a477f597d28d172789f06886806bc55\n",
            encoding="utf-8",
        )
        server = McpServer(McpService())
        initialized = server.handle_message({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {},
        })
        listed = server.handle_message({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
        scan_result = _call(server, 3, "dwi_scan_root", {"root": str(root)})
        if scan_result.get("isError"):
            return McpSmokeResult(True, False, False, False, False, False, False, "scan tool returned an MCP error")
        content = scan_result.get("structuredContent", {})
        scan_handle = content.get("scan_handle")
        if not isinstance(scan_handle, str):
            return McpSmokeResult(True, initialized is not None, listed is not None, False, False, False, False, "scan handle was not returned")
        findings_result = _call(server, 4, "dwi_list_findings", {"scan_handle": scan_handle})
        findings = findings_result.get("structuredContent", {}).get("findings", ())
        guarded = True
        note = "disposable scan had no engine-eligible cleanup finding"
        if findings:
            eligible = [item for item in findings if item.get("action_eligibility") == "eligible_for_explicit_action" and item.get("risk_label") in {"safe", "regeneratable"}]
            if eligible:
                review = _call(server, 5, "dwi_create_cleanup_review", {
                    "scan_handle": scan_handle,
                    "finding_ids": [eligible[0]["finding_id"]],
                })
                review_content = review.get("structuredContent", {})
                execution = _call(server, 6, "dwi_request_cleanup_execution", {"review_handle": review_content.get("review_handle")})
                guarded = execution.get("structuredContent", {}).get("error", {}).get("code") == McpErrorCode.HUMAN_CONFIRMATION_REQUIRED.value
                note = "eligible review stopped at the trusted human-confirmation boundary"
        return McpSmokeResult(
            True,
            initialized is not None,
            listed is not None and len(listed["result"]["tools"]) > 0,
            True,
            True,
            guarded,
            False,
            note,
        )
