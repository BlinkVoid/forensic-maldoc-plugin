"""Inventory reachable CFB directory metadata without opening user streams."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from importlib.metadata import PackageNotFoundError, distribution
from pathlib import Path
from typing import Literal

from .sandbox import WorkerError, run_worker
from .triage import MAX_DOCUMENT_BYTES, MAX_SOURCE_BYTES, OBSERVATION_LIMIT, _integer, _read_bounded

MAGIC = bytes.fromhex("D0 CF 11 E0 A1 B1 1A E1")
BASENAME = re.compile(
    r"[a-zA-Z0-9][a-zA-Z0-9._ -]{0,123}\.(?:ole|cfb|doc|xls|ppt)", re.IGNORECASE | re.ASCII,
)
VERSION = "0.47"
SOURCE_SHA256 = "dcce514efdcbd04fa689bc920531a1985df0837c92b57fe3af0c45c46f1bbd87"
SCOPE = "Reachable CFB directory metadata only; declared sizes, not verified stream contents."
INDICATORS = (
    "vba_storage", "vba_dir_name", "vba_project_name", "embedded_object_storage",
    "embedded_object_name", "package_name", "word_document_name", "excel_workbook_name",
    "powerpoint_document_name", "encrypted_package_name", "encryption_info_name",
)


@dataclass(frozen=True)
class OleEntry:
    kind: Literal["stream", "storage"]
    path_sha256: str
    depth: int
    indicator: str | None
    declared_size: int | None


@dataclass(frozen=True)
class OleCheck:
    tool: str
    version: str
    source_sha256: str
    scope: str
    indicators: list[str]
    status: Literal["completed", "partial", "not_checked", "error"]
    reason: str | None
    stream_count: int | None
    entries: list[OleEntry]


@dataclass(frozen=True)
class OleReport:
    schema_version: Literal[1]
    format: Literal["ole_cfb"]
    sha256: str
    size_bytes: int
    checks: list[OleCheck]


def _source() -> bytes:
    try:
        dist = distribution("olefile")
        if dist.version != VERSION:
            raise WorkerError("not_checked", "tool_version_mismatch")
        path = Path(dist.locate_file("olefile/olefile.py"))
        data = _read_bounded(path.parent, path.name, MAX_SOURCE_BYTES)
    except (PackageNotFoundError, OSError, ValueError):
        raise WorkerError("not_checked", "tool_unavailable") from None
    if hashlib.sha256(data).hexdigest() != SOURCE_SHA256:
        raise WorkerError("not_checked", "tool_digest_mismatch")
    return data


def _check(data: bytes) -> OleCheck:
    def result(status: Literal["completed", "partial", "not_checked", "error"], reason: str | None,
               count: int | None = None, entries: list[OleEntry] | None = None) -> OleCheck:
        return OleCheck("olefile", VERSION, SOURCE_SHA256, SCOPE, list(INDICATORS),
                        status, reason, count, entries or [])

    try:
        body = run_worker("ole", INDICATORS, OBSERVATION_LIMIT, _source(), data)
    except WorkerError as exc:
        return result(exc.status, exc.reason)
    try:
        reason, rows = body.get("partial_reason"), body["entries"]
        if reason not in (None, "parser_limit", "structure_incomplete") or not isinstance(rows, list) or len(rows) > OBSERVATION_LIMIT:
            raise ValueError("invalid worker report")
        count = _integer(body["stream_count"], MAX_DOCUMENT_BYTES // 128)
        entries = []
        for row in rows:
            kind, digest, indicator = row["kind"], row["path_sha256"], row["indicator"]
            if kind not in ("stream", "storage") or not re.fullmatch(r"[a-f0-9]{64}", digest):
                raise ValueError("invalid worker entry")
            if indicator is not None and indicator not in INDICATORS:
                raise ValueError("unknown worker indicator")
            size = row["declared_size"]
            if kind == "stream":
                size = _integer(size, 2**64 - 1)
            elif size is not None or indicator is None:
                raise ValueError("invalid storage entry")
            entries.append(OleEntry(kind, digest, _integer(row["depth"], 128, 1), indicator, size))
        observed = sum(entry.kind == "stream" for entry in entries)
        if observed > count or (reason is None and observed != count):
            raise ValueError("inconsistent stream count")
        return result("completed" if reason is None else "partial", reason, count, entries)
    except (KeyError, ValueError, TypeError):
        return result("error", "invalid_worker_report")


def triage_ole(staging: Path, name: str) -> OleReport:
    """Inspect CFB directory metadata from a single staged file."""
    if not BASENAME.fullmatch(name):
        raise ValueError("expected a plain staged .ole/.cfb/.doc/.xls/.ppt basename")
    try:
        data = _read_bounded(staging, name, MAX_DOCUMENT_BYTES)
    except OSError:
        raise ValueError("staged OLE file is unavailable or not a regular file") from None
    if not data.startswith(MAGIC):
        raise ValueError("expected the CFB signature at byte zero")
    return OleReport(1, "ole_cfb", hashlib.sha256(data).hexdigest(), len(data), [_check(data)])
