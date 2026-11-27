# File signatures and magic bytes

[Field book](Home.md) · Depth 1: identify

| Format signal | Bytes on disk | Meaning and boundary |
| --- | --- | --- |
| PDF | `25 50 44 46 2D` = `%PDF-` | The normative header starts at offset `0` and continues with a version, e.g. `31 2E 37` = `1.7`. A tolerant reader may find a nonconforming header later; record its exact offset instead of normalizing the evidence. The toolkit's assessment checks the prefix at offset `0`. [ISO 32000-1 §7.5.2][pdf] |
| OLE/CFB | `D0 CF 11 E0 A1 B1 1A E1` | Compound container header at offset `0`; not a specific Office application or a macro marker. [MS-CFB §2.2][cfb] |
| ZIP | `50 4B 03 04` = `PK` + local-header signature | A common ZIP prefix, not an OOXML identifier. Empty ZIPs can begin `50 4B 05 06` (end of central directory). For Office, inspect OPC parts, content types and relationships before claiming a particular package format. [PKWARE APPNOTE §4.3][zip] · [ECMA-376 Part 2][opc] |

## Terms to record

- **Byte offset:** zero-based position from the first byte. `0x20` is hexadecimal for decimal `32`. Keep the number base explicit when recording offsets from multiple tools.
- **Magic bytes:** a format-specific byte pattern, not a cryptographic signature, full parse, or proof that an application will open the file.
- **SHA-256:** a fingerprint of the exact staged bytes. Record byte count, source, and collection time alongside the hash; it cannot establish authorship or trust.
- **Format mismatch:** extension, media type, and byte evidence disagree. Note both signals. An encrypted OOXML file can legitimately have an outer CFB signature; the inner package remains a separate layer.

Next lookup: [PDF structure](PDF-Structure.md) · [CFB structure](OLE-CFB.md) · [metadata and encryption](Metadata-Encryption-Entropy.md)

[pdf]: https://opensource.adobe.com/dc-acrobat-sdk-docs/pdfstandards/PDF32000_2008.pdf
[cfb]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cfb/05060311-bfce-4b12-874d-71fd4ce63aea
[zip]: https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT
[opc]: https://ecma-international.org/publications-and-standards/standards/ecma-376/
