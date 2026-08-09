"""Command-line entry point for bounded DWI workspace analysis."""

from __future__ import annotations

import argparse
import sys

from .cleanup_cli import run_cleanup
from .report import json_report, json_system_report, table_report, table_system_report
from .scanner import WorkspaceScanError, scan_workspace
from .scan_control import ScanLimits
from .system_scan import SystemScanOptions, scan_system


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="dwi")
    commands = parser.add_subparsers(dest="command", required=True)
    scan = commands.add_parser("scan", help="scan one explicit workspace root")
    scan.add_argument("path")
    scan.add_argument("--json", action="store_true", dest="as_json")
    cleanup = commands.add_parser("cleanup", help="review and optionally quarantine one workspace in this process")
    cleanup.add_argument("path")
    cleanup.add_argument("--json", action="store_true", dest="as_json")
    cleanup.add_argument("--confirm-phrase", dest="confirmation_phrase")
    system = commands.add_parser("scan-system", help="scan approved local developer-storage roots")
    system.add_argument("--root", action="append", dest="roots", default=[])
    system.add_argument("--drive")
    system.add_argument("--allow-network", action="store_true", dest="allow_network")
    system.add_argument("--max-seconds", type=float, dest="max_seconds")
    system.add_argument("--max-nodes", type=int, dest="max_nodes")
    system.add_argument("--max-files", type=int, dest="max_files")
    system.add_argument("--json", action="store_true", dest="as_json")
    commands.add_parser("desktop", help="launch the Windows Desktop application")
    commands.add_parser("mcp", help="run the local stdio MCP server")
    args = parser.parse_args(argv)
    if args.command == "desktop":
        from .desktop import run_desktop

        return run_desktop()
    if args.command == "mcp":
        from .mcp import serve_stdio

        return serve_stdio()
    if args.command == "scan-system":
        try:
            has_explicit_roots = bool(args.roots)
            option_values = {
                "additional_roots": tuple(args.roots),
                "drive": args.drive,
                "include_fixed_drives": not has_explicit_roots,
                "include_user_profile": not has_explicit_roots,
                "include_global_storage": not has_explicit_roots,
                "allow_network": args.allow_network,
            }
            if any(value is not None for value in (args.max_seconds, args.max_nodes, args.max_files)):
                defaults = SystemScanOptions().limits
                option_values["limits"] = ScanLimits(
                    max_seconds=args.max_seconds if args.max_seconds is not None else defaults.max_seconds,
                    max_nodes=args.max_nodes if args.max_nodes is not None else defaults.max_nodes,
                    max_files=args.max_files if args.max_files is not None else defaults.max_files,
                )
            result = scan_system(SystemScanOptions(**option_values))
        except (ValueError, OSError) as error:
            print(f"dwi: system scan could not start: {error}", file=sys.stderr)
            return 2
        print(json_system_report(result) if args.as_json else table_system_report(result), end="")
        return 0
    if args.command == "cleanup":
        return run_cleanup(
            args.path,
            as_json=args.as_json,
            confirmation_phrase=args.confirmation_phrase,
        )
    try:
        result = scan_workspace(args.path)
    except WorkspaceScanError as error:
        print(f"dwi: {error}", file=sys.stderr)
        return 2
    print(json_report(result) if args.as_json else table_report(result), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
