"""Dependency-free clean-environment smoke for package entry points."""

from __future__ import annotations

import io
import json
import subprocess
import sys
import tempfile
from pathlib import Path


def main() -> int:
    repo = Path(__file__).resolve().parents[1]
    sys.path.insert(0, str(repo))
    subprocess.run([sys.executable, "-m", "dwi", "--version"], check=True)
    subprocess.run([sys.executable, "-m", "dwi", "--help"], check=True, stdout=subprocess.DEVNULL)
    with tempfile.TemporaryDirectory(prefix="dwi-clean-env-") as temporary:
        root = Path(temporary)
        cache = root / ".pytest_cache"
        cache.mkdir()
        (cache / "CACHEDIR.TAG").write_text("Signature: 8a477f597d28d172789f06886806bc55\n", encoding="utf-8")
        subprocess.run([sys.executable, "-m", "dwi", "scan", str(root), "--json"], check=True, stdout=subprocess.DEVNULL)
    from dwi.desktop import DESKTOP_VERSION
    from dwi.mcp import McpServer, McpService

    output = io.StringIO()
    server = McpServer(McpService())
    server.serve_stdio(io.StringIO(json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}) + "\n"), output)
    if not json.loads(output.getvalue())["result"]["tools"]:
        raise RuntimeError("MCP tool discovery returned no tools")
    print(json.dumps({"version": DESKTOP_VERSION, "mcp_tools": len(server.service.tool_definitions), "status": "ok"}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
