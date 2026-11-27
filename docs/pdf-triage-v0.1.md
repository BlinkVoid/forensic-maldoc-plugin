# PDF triage v0.1

## Goal and scope

Read one PDF explicitly placed in an analyst-controlled staging directory. Use Didier Stevens’ tools to report file-wide lexical signals and top-level object references through one deterministic Python report. The CLI emits the report as JSON; the optional stdio MCP server exposes the same report. An investigation skill turns observations into a defensible handoff. No LLM is required to produce evidence.

This is static triage, not a clean/malicious verdict or proof of behavior. Do not execute, render, extract, decompress object streams, fetch referenced content, upload evidence, or generate exploit material. Do not return raw document strings or code to the model. Office, RTF, email, Windows artifacts, and upstream tools by other authors are out of scope for this milestone.

## Contract and acceptance

| Item | Acceptance |
| --- | --- |
| Intake | A bounded single-file snapshot with validated basename, no symlinks or special files, and SHA-256 and byte length calculated from the exact inspected bytes. Missing, over-limit and rejected inputs fail without attempting analysis. |
| Inspection | PDFiD yields counts for a fixed set of indicator names. pdf-parser yields top-level indirect object number and generation for matching names before a stream; distinct appearances may reuse the same ID. No decoding or stream/attachment export. A PDFiD count and an object reference have different meanings and are not interchangeable. |
| Reporting | Stable versioned JSON across all three surfaces. Each check carries tool version, source digest and `completed`, `partial`, `not_checked`, or `error`. Only a completed check may report no matches for its scope. Flag scope limitations and stop/truncation without relaying sample-controlled text. |
| Runtime boundary | Approve only the two pinned scripts at startup/use, validate bytes before execution, stage only copies, run off-network in a bubblewrap namespace with a short deadline and capped memory/output. Missing confinement fails closed. The MCP tool accepts a basename only; roots are set by its human launcher. |
| Verification | Synthetic benign PDFs cover complete, incomplete and rejected inputs, false positives, source integrity, stable output and subprocess failures. Test stdio MCP over the wire; verify real upstream behavior and the sandbox separately. Do not claim production sandbox validation if the test host denies namespace creation. |
| Skill | Exercise a clean-but-limited case, a benign fixture with indicators, and a failed/incomplete scan; the workflow must not infer behavior, substitute tool output for a conclusion, or request payloads. |

## Upstream provenance

[Official downloads and hashes](https://blog.didierstevens.com/programs/pdf-tools/); [review snapshot](https://github.com/DidierStevens/DidierStevensSuite/tree/7d625d0b05c4638b981a2a2cc9a8481d7b73e56d). The following source bytes match the specific upstream ZIP members after verification of each official archive's published SHA-256. Both source headers say Didier Stevens placed the source in the public domain. The PDFiD source attributes its unused JSON helper separately; adapters do not depend on that helper. No bundle license is assumed and no upstream files are redistributed here. The analyst supplies just the two matching .py files; no configuration, plugins, other archive members or optional tool dependencies are loaded.

| Script | Version | SHA-256 of script |
| --- | --- | --- |
| `pdfid.py` | 0.2.10 | `e958a01f1c2596470f27d3c308061b85d7059ff476a58d74f1957a71b4f1248f` |
| `pdf-parser.py` | 0.7.14 | `a9fa2faa25e88ab0293543d14aa168ff21fc9fd25a0a8ad657b0dad3171214ac` |

## Implementation sequence

1. Define contract tests with an inert, valid PDF and failure cases before adding the package. Use a fake runner only for deterministic boundary/error assertions, not for claiming analyzer compatibility.
2. Implement the shared report and worker adapters, then the CLI and optional MCP transport. Verify tool output equivalence and confinement refusal.
3. Add the skills and reporting scenarios. Document setup, limits, validation results and any host blockers.

## Verification record

- Linux controlled run, 2026-11-28: both pinned upstream tools completed on generated benign PDFs in bubblewrap. The stdio MCP report matched the CLI JSON and Python API report using the real tools. A confinement probe could read the staged snapshot, but not an unstaged host file, and saw no host network interface. The opt-in suite passed all seven tests.
- The benign `/JS` metadata case is observable through both tools; neither test fixture contains executable content. Removing the end marker produces incomplete object coverage. Missing and changed tool sources produce `not_checked` without a worker call. Skill wording was reviewed against these outcomes; no independent model evaluation or real sample investigation has been performed.
- Ruff, wheel and source builds, and local documentation links passed. The source archive includes the applicable skills but no upstream analyzer source. The wheel contains the toolkit runtime; obtain skills from this checkout or the source archive.
