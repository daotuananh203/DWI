"""Command-line entry point for bounded DWI workspace analysis."""

from __future__ import annotations

import argparse
import sys

from .report import json_report, table_report
from .scanner import WorkspaceScanError, scan_workspace


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="dwi")
    commands = parser.add_subparsers(dest="command", required=True)
    scan = commands.add_parser("scan", help="scan one explicit workspace root")
    scan.add_argument("path")
    scan.add_argument("--json", action="store_true", dest="as_json")
    args = parser.parse_args(argv)
    try:
        result = scan_workspace(args.path)
    except WorkspaceScanError as error:
        print(f"dwi: {error}", file=sys.stderr)
        return 2
    print(json_report(result) if args.as_json else table_report(result), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
