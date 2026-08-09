"""Local-only MCP adapter for the untrusted DWI agent boundary."""

from .server import McpServer, serve_stdio
from .service import McpService
from .smoke import McpSmokeResult, run_mcp_smoke

__all__ = ["McpServer", "McpService", "McpSmokeResult", "run_mcp_smoke", "serve_stdio"]
