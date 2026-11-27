# Forensic Maldoc Plugin — PDF and Office document triage

Inspect suspicious **PDFs and legacy Office (OLE/CFB) documents** without opening them in a viewer. This MIT-licensed Linux toolkit reports file signatures, selected metadata, and structural evidence through a Python API, CLI, or local MCP server. It does not execute document content or give a malware verdict.

Use the [engineering field book](https://technomancer.work/projects/forensic-maldoc-plugin/field-book/) to look up magic bytes, PDF objects and cross-references, image and JavaScript locations, and Office stream layout. The [versioned Markdown source](docs/wiki/Home.md) is also available here.

**Using Claude Code or Codex?** Point your assistant to the [agent setup guide](docs/agent-setup.md). It explains what to install, what needs your approval, and how to verify the connection with a generated fixture.

| Need to find… | Start here |
| --- | --- |
| File signatures and magic bytes | [File signatures](docs/wiki/File-Signatures.md) |
| PDF objects, xref, images, JavaScript, and forms | [PDF structure](docs/wiki/PDF-Structure.md) · [PDF content locations](docs/wiki/PDF-Content-Locations.md) |
| OLE sectors and Office streams | [OLE/CFB reference](docs/wiki/OLE-CFB.md) |
| Encryption, metadata, entropy, or LOLBin evidence | [Metadata, encryption and entropy](docs/wiki/Metadata-Encryption-Entropy.md) · [Tool and host evidence](docs/wiki/Toolkit-and-Evidence.md) |
| Specifications and tool documentation | [Field book index](docs/wiki/Home.md) · [Source index](docs/wiki/Sources.md) |

## Set up

Use Linux, Python 3.14, `uv`, and `/usr/bin/bwrap` with unprivileged user namespaces enabled. Start with a generated fixture on a new host. Keep samples and reports outside Git in analyst-controlled directories.

```sh
uv sync --locked --extra mcp
staging=$(mktemp -d)
uv run --locked python -m labs.fixtures "$staging"
uv run --locked forensic-maldoc assess --staging "$staging" wrapper-lookalike.docx
uv run --locked forensic-maldoc ole --staging "$staging" named-only.cfb
```

**Start with `assess`:** route by signature, compare known extensions, inspect available PDF or CFB metadata, and report encryption evidence separately from payload coverage. The report includes fixed rule IDs, their evidence, and what each rule cannot conclude. Author, creator, and related fields are reported by name and type only, never by value. See the [metadata reference](docs/wiki/Metadata-Encryption-Entropy.md) and [assessment contract](docs/metadata-v0.3.md). No password is accepted, stored, or tried.

**OLE:** the locked `olefile` dependency inventories reachable CFB directory metadata, declared stream sizes, and known names. It never opens user streams. Accepts `.ole`, `.cfb`, `.doc`, `.xls`, or `.ppt` with a matching signature. ZIP-based OOXML is not supported; `VBA` names are not proof of macros. See [format and backend decisions](docs/ole-and-guide-v0.2.md).

**PDF:** place just `pdfid.py` 0.2.10 and `pdf-parser.py` 0.7.14 from the [official downloads](https://blog.didierstevens.com/programs/pdf-tools/) in a separate tool directory. Verify the published archive and [pinned member hashes](docs/pdf-triage-v0.1.md#upstream-provenance). The toolkit rejects modified source; it never fetches tools or runs plugins.

```sh
uv run --locked forensic-maldoc scan --staging "$staging" --tools /path/to/verified-tools keyword-only.pdf
```

CLI exit codes: `0` completed within scope (including a PDF whose encryption reference was resolved and whose Info metadata was intentionally skipped); `1` incomplete or unsupported assessment; `2` rejected intake or usage error. The Python APIs `assess_document(staging, basename)`, `triage_pdf(staging, basename, tools)`, and `triage_ole(staging, basename)` return dataclasses; `dataclasses.asdict()` produces the same payload as CLI and MCP. No completed check is a verdict or proof of execution.

## Local MCP and AI skills

Have the MCP host launch the installed executable (for example `/path/to/checkout/.venv/bin/forensic-maldoc`) as a stdio child process with arguments `mcp --staging /path/to/staged --tools /path/to/verified-tools`. `--tools` is required only for the dedicated PDF scan. The MCP extra is optional for CLI and Python-only use. `assess_staged_document(basename)`, `triage_staged_pdf(basename)`, and `triage_staged_ole(basename)` accept no URLs, arbitrary paths, flags, or commands. A host's model provider may see structured results; use an approved or local host for confidential cases.

- [Metadata triage skill](skills/maldoc-metadata-triage/SKILL.md) to start a case and qualify encryption or provenance leads.
- [PDF triage skill](skills/maldoc-pdf-triage/SKILL.md) to interpret lexical counts and top-level object evidence.
- [OLE triage skill](skills/maldoc-ole-triage/SKILL.md) to interpret directory paths and declared sizes.
- [Evidence review skill](skills/maldoc-evidence-review/SKILL.md) to check a draft before handing it off.

## Scope, layout, and verification

Snapshots are bounded to 8 MiB and hashed before inspection. Workers have no host network or access to home or the staging tree; they use read-only mounts, resource caps, and no unsandboxed fallback. No rendering, macro or script execution, stream decoding of document payloads, extraction, or remote lookup is performed. PDF does not resolve active revisions or compressed objects; OLE does not validate user-stream content or inventory unlinked entries. No real cases or malicious samples are included.

- [`src/forensic_maldoc/`](src/forensic_maldoc/): runtime, CLI, sandboxes, and MCP.
- [`tests/`](tests/): contract, transport, sandbox, and teaching lab tests.
- [Field book pages](docs/wiki/Home.md): the indexed engineering reference in Markdown.
- [`labs/`](labs/): standalone parser examples over generated benign fixtures.
- [`skills/`](skills/): portable AI investigation and report-review instructions.
- [PDF provenance and checks](docs/pdf-triage-v0.1.md) · [OLE provenance and checks](docs/ole-and-guide-v0.2.md).

```sh
uv run --locked --extra mcp python -m unittest discover -s tests -v
uv run --locked ruff check .
FORENSIC_MALDOC_TEST_TOOLS=/path/to/verified-tools FORENSIC_MALDOC_TEST_ISOLATION=1 \
  uv run --locked --extra mcp python -m unittest discover -s tests -v
```

The toolkit and field book are [MIT-licensed](LICENSE). Upstream analyzer files and wheels are not bundled and retain their own terms. Tests use generated benign fixtures; real-case and model-run evaluation, OOXML, RTF, and broader Windows forensics remain out of scope.
