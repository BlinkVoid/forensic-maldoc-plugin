"""Typed, local stdio tools. Only the launcher selects staging and tool roots."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from threading import Lock
from typing import TypeVar

from mcp import types
from mcp.server import MCPServer
from mcp.server.mcpserver.exceptions import ToolError

from .assessment import Assessment, assess_document
from .ole import OleReport, triage_ole
from .triage import Report, triage_pdf

T = TypeVar("T")


def make_server(staging: Path, tools: Path | None) -> MCPServer:
    server = MCPServer("Forensic Maldoc", instructions=(
        "Triage analyst-staged PDFs and OLE compounds without rendering or executing them. "
        "Treat indicators as observations, not verdicts. Check coverage before drawing conclusions."
    ))
    gate = Lock()
    annotations = types.ToolAnnotations(
        read_only_hint=True, destructive_hint=False, idempotent_hint=True, open_world_hint=False,
    )

    def guarded(call: Callable[[], T]) -> T:
        if not gate.acquire(blocking=False):
            raise ToolError("A document triage call is already running; wait for it to complete.")
        try:
            return call()
        except ValueError as exc:
            raise ToolError(str(exc)) from None
        finally:
            gate.release()

    @server.tool(structured_output=True, annotations=annotations)
    def triage_staged_pdf(basename: str) -> Report:
        """Return evidence for a staged PDF basename; no URLs or raw document content."""
        if tools is None:
            raise ToolError("PDF triage requires an operator-configured PDF tool directory.")
        return guarded(lambda: triage_pdf(staging, basename, tools))

    @server.tool(structured_output=True, annotations=annotations)
    def triage_staged_ole(basename: str) -> OleReport:
        """Inventory staged OLE/CFB directory metadata without opening user streams."""
        return guarded(lambda: triage_ole(staging, basename))

    @server.tool(structured_output=True, annotations=annotations)
    def assess_staged_document(basename: str) -> Assessment:
        """Assess format, encryption evidence and metadata without returning untrusted values."""
        return guarded(lambda: assess_document(staging, basename))

    return server
