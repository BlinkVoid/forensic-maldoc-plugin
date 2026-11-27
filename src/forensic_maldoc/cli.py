"""Human CLI and entry point for the local stdio MCP server."""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict
from pathlib import Path

from .assessment import assess_document
from .ole import triage_ole
from .triage import triage_pdf


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="forensic-maldoc")
    commands = parser.add_subparsers(dest="command", required=True)
    scan = commands.add_parser("scan", help="triage one staged PDF and emit JSON")
    ole = commands.add_parser("ole", help="inventory one staged OLE/CFB file and emit JSON")
    assess = commands.add_parser("assess", help="identify a staged document and assess its metadata")
    for command in (scan, ole, assess):
        command.add_argument("basename", help="basename of a file already staged by the analyst")
    mcp = commands.add_parser("mcp", help="serve the same evidence over local stdio")
    for command in (scan, ole, assess, mcp):
        command.add_argument("--staging", type=Path, required=True)
    scan.add_argument("--tools", type=Path, required=True)
    mcp.add_argument("--tools", type=Path, help="verified PDF tool directory; optional for OLE-only use")
    args = parser.parse_args(argv)
    if args.command == "mcp":
        try:
            from .mcp_server import make_server
        except ModuleNotFoundError as exc:
            if exc.name != "mcp":
                raise
            parser.exit(2, "The MCP extra is required: install forensic-maldoc-plugin[mcp].\n")
        make_server(args.staging, args.tools).run(transport="stdio")
        return 0
    try:
        if args.command == "assess":
            assessment = assess_document(args.staging, args.basename)
            print(json.dumps(asdict(assessment), indent=2, ensure_ascii=True))
            assessed = assessment.metadata.status == "completed" or (
                assessment.metadata.reason == "pdf_info_skipped_encryption"
            )
            return 0 if assessed else 1
        if args.command == "ole":
            report = triage_ole(args.staging, args.basename)
        else:
            report = triage_pdf(args.staging, args.basename, args.tools)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    print(json.dumps(asdict(report), indent=2, ensure_ascii=True))
    return 0 if all(check.status == "completed" for check in report.checks) else 1


if __name__ == "__main__":
    raise SystemExit(main())
