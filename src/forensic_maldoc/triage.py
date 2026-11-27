"""Collect deterministic evidence from pinned, isolated PDF analyzers."""

from __future__ import annotations

import hashlib
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from .sandbox import WorkerError
from .sandbox import run_worker as _run_worker

MAX_DOCUMENT_BYTES = 8 * 1024 * 1024
MAX_SOURCE_BYTES = 256 * 1024
OBSERVATION_LIMIT = 200
INDICATORS = (
    "/AA", "/EmbeddedFile", "/Encrypt", "/JBIG2Decode", "/JS", "/JavaScript",
    "/Launch", "/ObjStm", "/OpenAction", "/RichMedia", "/XFA",
)
PDFID_INDICATORS = tuple(name for name in INDICATORS if name != "/EmbeddedFile")
BASENAME = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9._ -]{0,123}\.pdf", re.IGNORECASE | re.ASCII)


@dataclass(frozen=True)
class Tool:
    name: str
    filename: str
    version: str
    sha256: str
    indicators: tuple[str, ...]
    scope: str


TOOLS = (
    Tool("pdfid", "pdfid.py", "0.2.10",
         "e958a01f1c2596470f27d3c308061b85d7059ff476a58d74f1957a71b4f1248f",
         PDFID_INDICATORS, "File-wide lexical counts; not proof of a parsed object or executed action."),
    Tool("pdf-parser", "pdf-parser.py", "0.7.14",
         "a9fa2faa25e88ab0293543d14aa168ff21fc9fd25a0a8ad657b0dad3171214ac",
         INDICATORS, "Names before streams in top-level indirect objects; no stream decoding or revision resolution."),
)


@dataclass(frozen=True)
class Observation:
    indicator: str
    count: int | None = None
    obfuscated: int | None = None
    object_number: int | None = None
    generation: int | None = None


@dataclass(frozen=True)
class Check:
    tool: str
    version: str
    source_sha256: str
    scope: str
    indicators: list[str]
    status: Literal["completed", "partial", "not_checked", "error"]
    reason: str | None
    observations: list[Observation]


@dataclass(frozen=True)
class Report:
    schema_version: Literal[1]
    sha256: str
    size_bytes: int
    checks: list[Check]


def _read_bounded(root: Path, name: str, cap: int) -> bytes:
    directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=directory)
    finally:
        os.close(directory)
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode):
            raise ValueError("not a regular file")
        if before.st_size > cap:
            raise ValueError("size limit exceeded")
        data = stream.read(cap + 1)
        after = os.fstat(stream.fileno())
        if len(data) > cap:
            raise ValueError("size limit exceeded")
        if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
            after.st_size, after.st_mtime_ns, after.st_ctime_ns,
        ) or len(data) != after.st_size:
            raise ValueError("file changed while reading")
        return data


def _load_script(root: Path, tool: Tool) -> bytes:
    try:
        data = _read_bounded(root, tool.filename, MAX_SOURCE_BYTES)
    except (OSError, ValueError):
        raise WorkerError("not_checked", "tool_unavailable") from None
    if hashlib.sha256(data).hexdigest() != tool.sha256:
        raise WorkerError("not_checked", "tool_digest_mismatch")
    return data


def _integer(value: object, maximum: int, minimum: int = 0) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError("invalid worker number")
    return value


def _check(tool: Tool, tools: Path, sample: bytes) -> Check:
    def result(status: Literal["completed", "partial", "not_checked", "error"],
               reason: str | None, observations: list[Observation] | None = None) -> Check:
        return Check(tool.name, tool.version, tool.sha256, tool.scope, list(tool.indicators),
                     status, reason, observations or [])

    try:
        source = _load_script(tools, tool)
        body = _run_worker(tool.name, tool.indicators, OBSERVATION_LIMIT, source, sample)
    except WorkerError as exc:
        return result(exc.status, exc.reason)

    try:
        rows = body["observations"]
        reason = body.get("partial_reason")
        if not isinstance(rows, list) or len(rows) > OBSERVATION_LIMIT or reason not in (
            None, "parser_limit", "pdf_header_unrecognized", "structure_incomplete",
        ):
            raise ValueError("invalid worker report")
        observations = []
        for row in rows:
            if not isinstance(row, dict) or row.get("indicator") not in tool.indicators:
                raise ValueError("invalid worker observation")
            indicator = row["indicator"]
            if tool.name == "pdfid":
                count = _integer(row.get("count"), len(sample), 1)
                obfuscated = _integer(row.get("obfuscated"), count)
                observations.append(Observation(indicator, count=count, obfuscated=obfuscated))
            else:
                observations.append(Observation(
                    indicator, object_number=_integer(row.get("object_number"), 2**31 - 1, 1),
                    generation=_integer(row.get("generation"), 65535),
                ))
        return result("completed" if reason is None else "partial", reason, observations)
    except (KeyError, ValueError, TypeError):
        return result("error", "invalid_worker_report")


def triage_pdf(staging: Path, name: str, tools: Path) -> Report:
    """Inspect one staged PDF by basename. Roots must be selected by the operator."""
    if not BASENAME.fullmatch(name):
        raise ValueError("expected a plain staged .pdf basename")
    try:
        data = _read_bounded(staging, name, MAX_DOCUMENT_BYTES)
    except OSError:
        raise ValueError("staged PDF is unavailable or not a regular file") from None
    if not re.match(rb"%PDF-[0-9]\.[0-9](?:\r|\n)", data):
        raise ValueError("expected a PDF version header at byte zero")
    return Report(1, hashlib.sha256(data).hexdigest(), len(data), [_check(t, tools, data) for t in TOOLS])
