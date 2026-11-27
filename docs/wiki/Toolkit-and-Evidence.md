# Toolkit coverage and host evidence

[Field book](Home.md) · Depth 3: interpret

## Which observation can I cite?

| Surface | What it reports | Important boundary |
| --- | --- | --- |
| `assess` | Signature/extension comparison, supported classic-PDF trailer references, selected Info/property field names and types, root Office wrapper names and declared sizes | No password check, XMP, payload verification, or Office application-record parse. Status applies only to checks that ran. |
| `scan`: PDFiD 0.2.10 | Lexical counts of selected name spellings | Name occurrence is not dictionary position, a defined action, or a current PDF revision. |
| `scan`: pdf-parser 0.7.14 | Selected indicators associated with top-level object number and generation | Not full object semantics, decoding, or revision/graph reconstruction. |
| `ole`: `olefile` 0.47 metadata API | Reachable directory entries, recognized names and declared stream sizes | No user-stream reads; not a macro validator, payload reader, or inventory of unlinked entries. |
| `oledump.py` | Upstream Didier Stevens stream-focused tool | Not this toolkit’s backend. It has different scope and can inspect stream contents. Do not attribute its findings to `ole`. |

Primary tool references: [Didier Stevens PDF Tools][didier-pdf], [Didier Stevens oledump][didier-ole], [olefile API][olefile]. The [toolkit’s PDF scope][scope-pdf] records the exact versions and provenance; see also [CFB scope][scope-cfb] and [assessment coverage][scope-meta]. The MCP and CLI report the same bounded evidence. Neither runs a reader, script, macro, or embedded command.

## LOLBins and endpoint evidence

A **LOLBin** is a legitimate binary that can also be misused. [MITRE ATT&CK T1218][attack] documents proxy execution through trusted binaries; not every process with such a name is proxy execution.

| Evidence | Supported conclusion |
| --- | --- |
| Executable name in a document | Static reference or text; not a process. |
| Process creation event | A specific image started on a particular host and time, as recorded. Include image path, process GUID/ID, user/session, and parent; preserve hashes/signature evidence when collected. |
| File-open record linked to the process chain | Stronger attribution, if the exact document identity, time and lineage agree. A process-image hash is not an attachment hash. |
| Block or audit event | Report what was blocked or logged; do not convert it into successful execution. |

[Sysmon Event 1][sysmon] is process creation, not a record of every file read. Follow-up network and image-load evidence depends on what was collected. A same-host timestamp alone does not prove causation. Compare known administrative activity before attributing intent. Keep the document observation, the process observation, and the linkage evidence separate in the report.

[didier-pdf]: https://blog.didierstevens.com/programs/pdf-tools/
[didier-ole]: https://blog.didierstevens.com/programs/oledump-py/
[olefile]: https://olefile.readthedocs.io/en/latest/Howto.html
[scope-pdf]: https://github.com/BlinkVoid/forensic-maldoc-plugin/blob/main/docs/pdf-triage-v0.1.md
[scope-cfb]: https://github.com/BlinkVoid/forensic-maldoc-plugin/blob/main/docs/ole-and-guide-v0.2.md
[scope-meta]: https://github.com/BlinkVoid/forensic-maldoc-plugin/blob/main/docs/metadata-v0.3.md
[attack]: https://attack.mitre.org/techniques/T1218/
[sysmon]: https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
