---
name: maldoc-ole-triage
description: Inventory an analyst-staged legacy Office or OLE/CFB artifact without opening streams; report the evidence and its limits.
---

# Triage an OLE compound without opening it

1. Use only a staged, analyst-authorized `.ole`, `.cfb`, `.doc`, `.xls`, or `.ppt` basename. The tool expects CFB bytes at offset zero. A ZIP/OOXML document, a mismatched extension, or a signature-only damaged file is not an invitation to rename, unpack, or open it.
2. Call `triage_staged_ole` with the basename, or use the toolkit’s `ole` command from the analyst’s trusted terminal. Never work around a failed sandbox or tool provenance check. Do not ask for macros or payloads.
3. Report the artifact SHA-256 and byte count, the `olefile` version, check status and reason. State that only reachable CFB directory metadata was inspected. `stream_count` counts discovered named streams, not validated content. `declared_size` is a directory field. An opaque `path_sha256` is an evidence reference, not a stream-content hash; include it when citing a specific entry.
4. Interpret labels narrowly. `vba_storage` or `vba_dir_name` means a recognized spelling in the directory, not an executable VBA project. `encrypted_package_name` is a reason to qualify coverage, not proof of contents. The inventory excludes unlinked rows, arbitrary names, and all user-stream contents. A partial report supports positive observations, not absence claims.
5. Separate observations, hypotheses, and one next defensive action. If the user reports opening the file, preserve the timeline and recommend authorized endpoint review instead of inferring execution from the document.

For file layout and content locations, use the [OLE/CFB reference](../../docs/wiki/OLE-CFB.md). For a consequential handoff, use `maldoc-evidence-review`.
