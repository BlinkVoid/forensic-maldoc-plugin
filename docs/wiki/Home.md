# Maldoc field book

A lookup reference for engineers doing read-only inspection of suspicious documents. Each page answers a format or evidence question. Levels describe how deep the reference goes; they are not prerequisites.

| Depth | Lookup | Use it to find |
| --- | --- | --- |
| 1 · Identify | [Magic bytes and format signals](File-Signatures.md) | PDF `%PDF-` (`25 50 44 46 2D`), CFB magic, ZIP vs. OOXML, file offsets and hashes |
| 2 · Navigate | [PDF file structure and xref](PDF-Structure.md) | Header, indirect objects, trailer, catalog, page tree, xref streams, incremental revisions |
| 2 · Navigate | [PDF content and interactive elements](PDF-Content-Locations.md) | Text, fonts, raster images, inline images, JavaScript, annotations, forms and attachments |
| 2 · Navigate | [OLE/CFB structure and Office content](OLE-CFB.md) | Header offsets, FAT, DIFAT, MiniFAT, directory, document streams, VBA and embedded data |
| 3 · Interpret | [Metadata, encryption and entropy](Metadata-Encryption-Entropy.md) | PDF Info vs. XMP, Office property sets, encryption declarations and byte-range measurements |
| 3 · Interpret | [Tool coverage and host evidence](Toolkit-and-Evidence.md) | What PDFiD, pdf-parser, `olefile`, and this toolkit actually observe; what LOLBin telemetry proves |
| All | [Source index](Sources.md) | Primary specifications, tool documentation, and limits of each source |

**Read locations as data.** An object type, stream name or reference can show what the document declares. Reader behavior, an attempted action, and execution on a host are separate observations. Do not open the sample, evaluate script, follow embedded URLs, or treat a partial report as a negative finding.
