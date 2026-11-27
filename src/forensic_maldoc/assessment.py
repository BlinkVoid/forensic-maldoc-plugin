"""Read-only intake, bounded metadata evidence, and explainable triage rules."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from .ole import MAGIC, VERSION
from .ole import _source as ole_source
from .sandbox import WorkerError, run_worker
from .triage import MAX_DOCUMENT_BYTES, _read_bounded

Format = Literal["pdf", "ole_cfb", "zip_signature", "unknown"]
Encryption = Literal[
    "unknown", "not_indicated", "dictionary_referenced", "office_wrapper_indicated",
    "office_wrapper_empty", "office_wrapper_incomplete",
]
PDF_FORMAT = re.compile(rb"%PDF-[0-9]\.[0-9](?:\r|\n)")
BASENAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._ -]{0,127}")
PDF_FIELDS = frozenset({
    "title", "author", "subject", "creator", "producer", "keywords", "creation_date", "modification_date",
})
OLE_FIELDS = frozenset({
    "title", "subject", "author", "keywords", "last_saved_by", "creation_date", "modification_date", "application",
})
FORMAT_EXTENSIONS: dict[str, frozenset[str]] = {
    ".pdf": frozenset({"pdf"}), ".ole": frozenset({"ole_cfb"}), ".cfb": frozenset({"ole_cfb"}),
    **dict.fromkeys((".doc", ".xls", ".ppt"), frozenset({"ole_cfb"})),
    **dict.fromkeys((".docx", ".xlsx", ".pptx", ".docm", ".xlsm", ".pptm"), frozenset({"ole_cfb", "zip_signature"})),
    ".zip": frozenset({"zip_signature"}),
}
ISSUES = frozenset({
    "unsupported_pdf_structure", "unresolved_pdf_encryption_reference", "unresolved_pdf_info_reference",
    "ole_directory_warnings", "ole_summary_size_outside_scope", "ole_summary_unreadable",
})


@dataclass(frozen=True)
class Field:
    name: str
    kind: Literal["text", "timestamp", "unexpected_type"]


@dataclass(frozen=True)
class Metadata:
    status: Literal["completed", "partial", "not_checked", "error"]
    reason: str | None
    source: str | None
    source_sha256: str | None
    fields: list[Field]


@dataclass(frozen=True)
class EncryptionEvidence:
    state: Encryption
    scope: str


@dataclass(frozen=True)
class Finding:
    rule_id: str
    evidence: list[str]
    explanation: str
    limitation: str


@dataclass(frozen=True)
class Assessment:
    schema_version: Literal[1]
    sha256: str
    size_bytes: int
    format: Format
    extension: str | None
    encryption: EncryptionEvidence
    metadata: Metadata
    payload_status: Literal["not_inspected"]
    findings: list[Finding]


def _format(raw: bytes) -> Format:
    if PDF_FORMAT.match(raw):
        return "pdf"
    if raw.startswith(MAGIC):
        return "ole_cfb"
    if raw.startswith((b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")):
        return "zip_signature"
    return "unknown"


def _inspect(fmt: Format, raw: bytes) -> tuple[Metadata, Encryption, dict]:
    if fmt not in ("pdf", "ole_cfb"):
        reason = "zip_not_unpacked" if fmt == "zip_signature" else "unknown_format"
        return Metadata("not_checked", reason, None, None, []), "unknown", {}
    pdf = fmt == "pdf"
    engine = "classic-pdf-metadata/1" if pdf else f"olefile/{VERSION}"
    digest = None
    try:
        source = Path(__file__).with_name("pdf_metadata.py").read_bytes() if pdf else ole_source()
        digest = hashlib.sha256(source).hexdigest()
        reply = run_worker("pdf-metadata" if pdf else "ole-metadata", (), 16, source, raw)
    except WorkerError as exc:
        return Metadata(exc.status, exc.reason, engine, digest, []), "unknown", {}
    except OSError:
        return Metadata("not_checked", "tool_unavailable", engine, None, []), "unknown", {}
    try:
        issue = reply.get("issue")
        encryption = reply.get("encryption", "unknown")
        allowed = ("unknown", "not_indicated", "dictionary_referenced") if pdf else (
            "unknown", "office_wrapper_indicated", "office_wrapper_empty", "office_wrapper_incomplete",
        )
        if (issue is not None and issue not in ISSUES) or encryption not in allowed:
            raise ValueError("unexpected worker state")
        fields = []
        seen = set()
        for row in reply.get("fields", []) if issue is None else []:
            name, kind = row["name"], row["kind"]
            if name not in (PDF_FIELDS if pdf else OLE_FIELDS) or name in seen or kind not in (
                "text", "timestamp", "unexpected_type",
            ):
                raise ValueError("unexpected metadata field")
            seen.add(name)
            fields.append(Field(name, kind))
        if issue is not None:
            metadata = Metadata("partial", issue, engine, digest, fields)
        elif pdf and encryption == "dictionary_referenced":
            metadata = Metadata("not_checked", "pdf_info_skipped_encryption", engine, digest, [])
        else:
            metadata = Metadata("completed", None, engine, digest, fields)
        return metadata, encryption, reply
    except (KeyError, TypeError, ValueError):
        return Metadata("error", "invalid_worker_report", engine, digest, []), "unknown", {}


def _findings(fmt: Format, ext: str | None, state: Encryption, metadata: Metadata, detail: dict) -> list[Finding]:
    findings = []
    if ext in FORMAT_EXTENSIONS and fmt != "unknown" and fmt not in FORMAT_EXTENSIONS[ext]:
        findings.append(Finding("extension_mismatch", ["format", "extension"],
                                "The recognized extension and observed signature disagree.",
                                "A mismatch can be accidental and does not establish intent."))
    if state == "dictionary_referenced":
        findings.append(Finding("pdf_encrypt_dictionary", ["pdf.trailer.Encrypt"],
                                "The supported trailer points to a dictionary through the xref table.",
                                "This does not validate the security handler or show that opening requires a password."))
    if state.startswith("office_wrapper_"):
        explanation = {
            "office_wrapper_indicated": "Both root wrapper stream names have nonzero declared sizes.",
            "office_wrapper_empty": "Both root wrapper stream names exist, but at least one declares zero bytes.",
            "office_wrapper_incomplete": "Only one of the expected root wrapper stream names was observed.",
        }[state]
        findings.append(Finding(state, ["cfb.root.EncryptionInfo", "cfb.root.EncryptedPackage"], explanation,
                                "This is directory evidence only; the streams and inner document were not checked."))
    if detail.get("catalog_action") is True:
        findings.append(Finding("pdf_catalog_action_key", ["pdf.catalog.OpenAction_or_AA"],
                                "A recognized action key is present in the catalog.",
                                "The action value and reader behavior were not evaluated; a destination can be benign."))
    if detail.get("vba_dir_name") is True:
        findings.append(Finding("ole_vba_directory_name", ["cfb.directory.VBA/dir"],
                                "A reachable stream name matches the VBA directory marker.",
                                "No macro content, validity, or execution was established."))
    wrong_types = [f"metadata.fields.{field.name}" for field in metadata.fields if field.kind == "unexpected_type"]
    if wrong_types:
        findings.append(Finding("metadata_unexpected_type", wrong_types, "A selected property has an unexpected type.",
                                "Producer variations or malformed metadata can cause this; it is not a verdict."))
    return findings


def assess_document(staging: Path, basename: str) -> Assessment:
    """Identify a staged file without relying on its extension and assess available metadata."""
    if not BASENAME.fullmatch(basename):
        raise ValueError("expected a plain staged basename")
    try:
        raw = _read_bounded(staging, basename, MAX_DOCUMENT_BYTES)
    except OSError:
        raise ValueError("staged document is unavailable or not a regular file") from None
    fmt = _format(raw)
    suffix = Path(basename).suffix.lower()
    ext = suffix if suffix in FORMAT_EXTENSIONS else None
    metadata, state, detail = _inspect(fmt, raw)
    scope = {
        "pdf": "One supported classic trailer and referenced dictionaries; no password or decryption check.",
        "ole_cfb": "Reachable root stream names and declared sizes; legacy encryption was not checked.",
        "zip_signature": "Signature only; archive contents and encryption were not checked.",
        "unknown": "No supported signature; encryption was not checked.",
    }[fmt]
    return Assessment(1, hashlib.sha256(raw).hexdigest(), len(raw), fmt, ext,
                      EncryptionEvidence(state, scope), metadata, "not_inspected",
                      _findings(fmt, ext, state, metadata, detail))
