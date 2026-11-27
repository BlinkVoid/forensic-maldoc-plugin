# OLE and CFB: sectors, directory entries and Office content

[Field book](Home.md) · Depth 2: navigate · [Magic bytes](File-Signatures.md)

**CFB** is the Compound File Binary container. A **storage** is folder-like; a **stream** is file-like. Legacy Office applications use CFB to store application-specific records, but many non-Office formats use CFB too. An embedded OLE object can itself use a compound container; the outer filename or signature does not identify the object inside.

## Header byte map

Offsets are hexadecimal, counted from byte zero. Multi-byte fields are little-endian. See [MS-CFB §2.2][header].

| Offset | Length | Field |
| --- | --- | --- |
| `0x00` | 8 | Signature `D0 CF 11 E0 A1 B1 1A E1` |
| `0x1A` | 2 | Major version: `3` or `4` |
| `0x1C` | 2 | Byte order: stored `FE FF`, value `0xFFFE` |
| `0x1E` | 2 | Sector shift: `9` (512-byte sectors) or `12` (4096-byte sectors) |
| `0x20` | 2 | Mini-sector shift: `6` (64 bytes) |
| `0x2C` | 4 | Number of FAT sectors |
| `0x30` | 4 | First directory sector ID |
| `0x38` | 4 | Mini-stream cutoff: 4096 bytes |
| `0x3C` | 4 | First MiniFAT sector ID |
| `0x44` | 4 | First extended DIFAT sector ID |
| `0x4C` | 436 | The 109 header DIFAT entries |

```text
header / DIFAT -> locations of regular FAT sectors
FAT[s]          -> next regular sector in a chain
first dir SID   -> FAT chain -> 128-byte directory entries
root entry      -> root mini stream (regular sectors)
MiniFAT         -> chain of 64-byte slots inside that mini stream
```

A regular sector ID `s` maps to byte offset `(s + 1) × sector_size`; the header occupies the first sector-sized slot. A mini-sector ID is an index **within the root mini stream**, not a physical file offset. Directory entries have a name, an object type, relationship IDs and a declared stream size. A sibling ID stays within a storage's children; a child ID starts a new level. Follow reachable entries from the root rather than treating physical directory order as a path. See [MS-CFB §§2.3–2.6][cfb].

## Where Office structures usually sit

| Content | Location or evidence lead | What the name alone does not establish |
| --- | --- | --- |
| Word binary document | `WordDocument`; the File Information Block (FIB) identifies the selected `0Table` or `1Table` stream. [MS-DOC §2.1][doc] | A valid Word file, its contents, or encryption state. |
| Excel binary workbook | `Workbook` stream in the BIFF8 format. [MS-XLS §2.1][xls] | Ordinary worksheet data, formulas, or the presence or absence of VBA. |
| PowerPoint binary presentation | `PowerPoint Document` and `Current User` streams. [MS-PPT §2.1][ppt] | A readable set of slides or their embedded objects. |
| VBA project | A VBA storage may be nested within an application-specific storage. Its `dir` stream describes project information, references and modules; module streams hold module data. [MS-OVBA §2.3.4.2][ovba] | Valid or readable macro bytes, a runnable entry point, or execution. |
| Office metadata | `\x05SummaryInformation` and `\x05DocumentSummaryInformation` property streams; `\x05` denotes the leading control character, not printed filename text. [MS-OSHARED §2.3.3.2.1][properties] | Verified author, provenance, timeline, or what the inner document contains. |
| Encrypted OOXML package | Root `EncryptionInfo` and `EncryptedPackage` in the outer CFB. [MS-OFFCRYPTO][crypto] | Correct security metadata, nonempty payload, mandatory opening password, or a successful decryption. |

For ordinary ZIP-based OOXML, start with the [ECMA-376 Part 2 package][opc]: `[Content_Types].xml` declares part types, and `/_rels/.rels` identifies package-level relationships, including the main document part. Parts and their relationship files locate media and embedded data; names such as `word/media/…` are common conventions, not the authoritative link. This kit does not walk OOXML relationships or application streams.

[header]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cfb/05060311-bfce-4b12-874d-71fd4ce63aea
[cfb]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cfb/53989ce4-7b05-4f8d-829b-d08d6148375b
[doc]: https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-doc/
[xls]: https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-xls/
[ppt]: https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-ppt/
[ovba]: https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-ovba/3d07f2c3-dee0-4ae3-b91f-3e32b789c534
[properties]: https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-oshared/11b56127-35f4-4bfa-a23f-23935a6edf54
[crypto]: https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-offcrypto/7ffe54c5-a76c-4eec-9690-dcc4640aac83
[opc]: https://ecma-international.org/publications-and-standards/standards/ecma-376/
