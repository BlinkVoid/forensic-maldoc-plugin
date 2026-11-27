# OLE/CFB and beginner field guide

## Scope and acceptance

- Add `triage_ole(staging, basename)`, `forensic-maldoc ole`, and the typed stdio tool `triage_staged_ole`. Keep the existing PDF API and command/schema compatible. Only accept analyst-staged `.ole`, `.cfb`, `.doc`, `.xls`, or `.ppt` with the CFB signature at byte zero; those extensions alone are not proof of type. Snapshots, hash, per-check status and closed failure semantics match PDF triage. ZIP-based OOXML is a separate format, not covered here.
- Inventory reachable named CFB streams and selected storage/stream indicators, with bounded stable path hashes, depth, fixed labels, and declared sizes. No raw names, content reads of user streams, macros, embedded-object extraction, passwords, decryption, rendering, or execution. Do not conflate a named directory entry with readable content. A truncation or structural warning becomes `partial`.
- Use `olefile` 0.47 through its metadata-only interface inside the existing unprivileged sandbox. Reuse the version and SHA-256 pinned source-copy pattern. URLs, paths, and arbitrary callable flags are not accepted. Validate input paths, scope, malformed-container handling, positive marker and no marker cases, and Python/CLI/MCP parity without running Office.
- Document PDF object/xref structure, CFB header/DIFAT/FAT/directory/MiniFAT, and the limits of inference in the [field book](wiki/Home.md). The narrowly scoped example parsers use only generated benign fixtures and are not called by the production toolkit.

## Upstream decision and provenance

[Didier Stevens’ oledump documentation](https://blog.didierstevens.com/programs/oledump-py/) and [pinned source](https://github.com/DidierStevens/DidierStevensSuite/blob/7d625d0b05c4638b981a2a2cc9a8481d7b73e56d/oledump.py#L1802-L1822) are references for OLE investigation. The pinned `oledump.py` is 0.0.85 (SHA-256 `9a18a2b5ab877be8d86d218b8933933ce2be9dfd3cdcb1d971da5e27765b73eb`); its header declares the source public domain, but its stream enumeration opens stream contents. For the first metadata-only release, use the same underlying [olefile API](https://olefile.readthedocs.io/en/latest/Howto.html) directly. Do not load `oledump`, its plugins or decoders.

[PyPI olefile 0.47](https://pypi.org/project/olefile/0.47/) supplies the separate [BSD-2-Clause dependency](https://olefile.readthedocs.io/en/latest/License.html), maintained in the lockfile. Verified wheel SHA-256 `543c7da2a7adadf21214938bb79c83ea12b473a4b6ee4ad4bf854e7715e13d1f`. The standalone member `olefile/olefile.py` has SHA-256 `dcce514efdcbd04fa689bc920531a1985df0837c92b57fe3af0c45c46f1bbd87`. Only that verified source is copied into a worker for each call. The package distribution retains its own license; neither source nor wheel is bundled with this project.

## Sequence

1. Write and witness a behavioral failure on a generated, inert CFB fixture.
2. Add the OLE inventory adapter and expose it with the existing sandbox, CLI, and stdio transport. Verify exact report parity and PDF regression.
3. Validate commands, expected findings, refusal branches, and reference links against generated fixtures.

## Verification record

The Linux opt-in suite exercises actual sandboxed OLE and pinned PDF backends, structured MCP/CLI/Python report parity, CFB type mismatch, symlink refusal, truncated CFB, opaque unknown names, and both lab parsers. The labs reject an incorrect PDF xref pointer and a cyclic CFB directory sector chain. No Office renderer, macro, or live malware was run. The field guide and skill scenarios are calibrated to the synthetic results; they have not undergone a novice usability study or a model-run evaluation.
