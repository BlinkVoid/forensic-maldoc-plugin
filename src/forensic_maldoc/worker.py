"""Worker entrypoint. It receives only the pinned backend and a single snapshot."""

from __future__ import annotations

import contextlib
import hashlib
import json
import re
import resource
import runpy
import sys
from datetime import datetime
from pathlib import Path
from typing import Any


@contextlib.contextmanager
def _quiet_stdout():
    # The backend may print diagnostics containing untrusted file content. Do not
    # buffer these or allow them to enter the worker protocol.
    with contextlib.redirect_stdout(sys.stderr):
        yield


def inspect_pdfid(api: dict[str, Any], sample: Path, indicators: tuple[str, ...]) -> dict:
    doc = api["PDFiD"](str(sample), allNames=False, extraData=False, disarm=False, force=False)
    root = doc.documentElement
    if root.getAttribute("ErrorOccured") != "False":
        raise ValueError("PDFiD failed")
    if root.getAttribute("IsPDF") != "True":
        return {"observations": [], "partial_reason": "pdf_header_unrecognized"}
    values = {}
    for node in root.getElementsByTagName("Keyword"):
        name = node.getAttribute("Name")
        if name in indicators:
            values[name] = (int(node.getAttribute("Count")), int(node.getAttribute("HexcodeCount")))
    if set(values) != set(indicators):
        raise ValueError("unexpected PDFiD indicator inventory")
    return {"observations": [
        {"indicator": name, "count": values[name][0], "obfuscated": values[name][1]}
        for name in indicators if values[name][0]
    ]}


def inspect_objects(api: dict[str, Any], sample: Path, indicators: tuple[str, ...], limit: int) -> dict:
    observations = []
    objects = 0
    with sample.open("rb") as stream:
        stream.seek(max(0, sample.stat().st_size - 1024))
        has_eof = bool(re.search(rb"(?:\r|\n)%%EOF[\x00\x09\x0a\x0c\x0d\x20]*\Z", stream.read()))
        stream.seek(0)
        parser = api["cPDFParser"](stream, extract=True)
        while (element := parser.GetObject()) is not None:
            if element.type == api["PDF_ELEMENT_MALFORMED"]:
                return {"observations": observations, "partial_reason": "structure_incomplete"}
            if element.type != api["PDF_ELEMENT_INDIRECT_OBJECT"]:
                continue
            objects += 1
            if objects > 4096:
                return {"observations": observations, "partial_reason": "parser_limit"}
            for name in indicators:
                if element.ContainsName(name):
                    if len(observations) == limit:
                        return {"observations": observations, "partial_reason": "parser_limit"}
                    observations.append({"indicator": name, "object_number": element.id,
                                         "generation": element.version})
    return {"observations": observations, "partial_reason": None if objects and has_eof else "structure_incomplete"}


def _ole_indicator(path: list[str], kind: str) -> str | None:
    folded = [part.casefold() for part in path]
    last = folded[-1]
    if kind == "storage":
        return {"vba": "vba_storage", "objectpool": "embedded_object_storage"}.get(last)
    if len(folded) >= 2 and folded[-2] == "vba":
        return {"dir": "vba_dir_name", "_vba_project": "vba_project_name"}.get(last)
    return {
        "\x01ole10native": "embedded_object_name", "package": "package_name",
        "worddocument": "word_document_name", "workbook": "excel_workbook_name",
        "book": "excel_workbook_name", "powerpoint document": "powerpoint_document_name",
        "encryptedpackage": "encrypted_package_name", "encryptioninfo": "encryption_info_name",
    }.get(last)


def inspect_ole(api: dict[str, Any], sample: Path, indicators: tuple[str, ...], limit: int) -> dict:
    entries = []
    partial = None
    with sample.open("rb") as stream, api["OleFileIO"](stream, write_mode=False) as container:
        streams = container.listdir(streams=True, storages=False)
        storages = container.listdir(streams=False, storages=True)
        for paths, kind in ((streams, "stream"), (storages, "storage")):
            for path in paths:
                if not 1 <= len(path) <= 128:
                    partial = "parser_limit"
                    continue
                indicator = _ole_indicator(path, kind)
                if kind == "storage" and indicator is None:
                    continue
                if indicator is not None and indicator not in indicators:
                    raise ValueError("unknown OLE marker")
                if len(entries) == limit:
                    partial = "parser_limit"
                    break
                canonical = json.dumps(path, ensure_ascii=True, separators=(",", ":")).encode("ascii")
                entries.append({
                    "kind": kind, "path_sha256": hashlib.sha256(canonical).hexdigest(),
                    "depth": len(path), "indicator": indicator,
                    "declared_size": container.get_size(path) if kind == "stream" else None,
                })
        if container.parsing_issues and partial is None:
            partial = "structure_incomplete"
    return {"entries": entries, "stream_count": len(streams), "partial_reason": partial}


def inspect_ole_metadata(api: dict[str, Any], sample: Path) -> dict:
    with sample.open("rb") as stream, api["OleFileIO"](stream, write_mode=False) as container:
        streams = container.listdir(streams=True, storages=False)
        root = {path[0].casefold(): path for path in streams if len(path) == 1}
        names = ("encryptioninfo", "encryptedpackage")
        present = [name for name in names if name in root]
        state = "unknown"  # Legacy Office can declare encryption inside application streams.
        if len(present) == 2:
            state = "office_wrapper_indicated" if all(container.get_size(root[n]) > 0 for n in names) else "office_wrapper_empty"
        elif present:
            state = "office_wrapper_incomplete"
        result: dict[str, Any] = {
            "encryption": state,
            "vba_dir_name": any(_ole_indicator(path, "stream") == "vba_dir_name" for path in streams),
        }
        if container.parsing_issues:
            return {**result, "issue": "ole_directory_warnings"}
        summary = root.get("\x05summaryinformation")
        if summary is None:
            return {**result, "fields": []}
        if not 48 <= container.get_size(summary) <= 64 * 1024:
            return {**result, "issue": "ole_summary_size_outside_scope"}
        try:
            properties = container.getproperties(summary, convert_time=True)
        except (OSError, ValueError, IndexError, OverflowError):
            return {**result, "issue": "ole_summary_unreadable"}
        if container.parsing_issues:
            return {**result, "issue": "ole_summary_unreadable"}
        fields = {2: "title", 3: "subject", 4: "author", 5: "keywords",
                  8: "last_saved_by", 12: "creation_date", 13: "modification_date",
                  18: "application"}
        rows = []
        for key, name in fields.items():
            if key not in properties:
                continue
            value = properties[key]
            if key in (12, 13):
                kind = "timestamp" if isinstance(value, datetime) else "unexpected_type"
            else:
                kind = "text" if isinstance(value, (str, bytes)) else "unexpected_type"
            rows.append({"name": name, "kind": kind})
        return {**result, "fields": rows}


def inspect(tool: str, source: Path, sample: Path, indicators: tuple[str, ...], limit: int) -> dict:
    with _quiet_stdout():
        backend = runpy.run_path(str(source))
        if tool == "pdfid":
            return inspect_pdfid(backend, sample, indicators)
        if tool == "pdf-parser":
            return inspect_objects(backend, sample, indicators, limit)
        if tool == "ole":
            return inspect_ole(backend, sample, indicators, limit)
        if tool == "ole-metadata":
            return inspect_ole_metadata(backend, sample)
        if tool == "pdf-metadata":
            return backend["inspect_metadata"](sample.read_bytes())
        raise ValueError("unrecognized backend")


def main() -> None:
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_FSIZE, (0, 0))
    resource.setrlimit(resource.RLIMIT_AS, (256 * 1024**2, 256 * 1024**2))
    resource.setrlimit(resource.RLIMIT_CPU, (5, 5))
    tool, limit, *indicators = sys.argv[1:]
    sample = Path("/sample.cfb" if tool in ("ole", "ole-metadata") else "/sample.pdf")
    result = inspect(tool, Path("/analyzer.py"), sample, tuple(indicators), int(limit))
    print(json.dumps(result, ensure_ascii=True, separators=(",", ":")))


if __name__ == "__main__":
    main()
