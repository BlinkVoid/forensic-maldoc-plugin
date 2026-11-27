# Sources and citation index

[Field book](Home.md)

Use the specification for format facts. Use a tool author's documentation or this project's contracts for what a particular check reports. Use endpoint documentation for what a log event records. These are different sources of evidence.

## Format specifications

| Source | Sections used for |
| --- | --- |
| [ISO 32000-1:2008 (PDF 1.7), Adobe-hosted text](https://opensource.adobe.com/dc-acrobat-sdk-docs/pdfstandards/PDF32000_2008.pdf) | §§7.3–7.9: syntax, file structure, encryption, catalog/page traversal, names and resources. §§8.9–8.10: images and Form XObjects. §9: text. §§12.5–12.7: annotations, actions, JavaScript, fields. §14.3: metadata. The numbered citations in this field book refer to this edition, not PDF 2.0. |
| [Microsoft MS-CFB](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cfb/53989ce4-7b05-4f8d-829b-d08d6148375b) | §§2.2–2.6: header, FAT/DIFAT, MiniFAT/mini stream, directory records and relationship trees. |
| [MS-DOC](https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-doc/), [MS-XLS](https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-xls/), [MS-PPT](https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-ppt/) | §2.1 in each: storage and stream layout for Word, Excel and PowerPoint binary formats. |
| [MS-OVBA §2.3.4.2](https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-ovba/3d07f2c3-dee0-4ae3-b91f-3e32b789c534) | The compressed `dir` stream and the kinds of records it declares. |
| [MS-OSHARED §2.3.3.2.1](https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-oshared/11b56127-35f4-4bfa-a23f-23935a6edf54) | SummaryInformation property-set identity and stream naming. |
| [MS-OFFCRYPTO §3.8](https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-offcrypto/7ffe54c5-a76c-4eec-9690-dcc4640aac83) | One wrapper example showing the relationship between `EncryptionInfo` and `EncryptedPackage`, not all encryption families. |
| [PKWARE ZIP APPNOTE](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) and [ECMA-376 Part 2](https://ecma-international.org/publications-and-standards/standards/ecma-376/) | ZIP record signatures, then Open Packaging Conventions content types, parts and relationships. |

## Tool and interpretation sources

| Source | Use and evidence boundary |
| --- | --- |
| [Didier Stevens: PDF Tools](https://blog.didierstevens.com/programs/pdf-tools/) | PDFiD is a lexical scanner; pdf-parser organizes elements/objects. The official release listing provides archive hashes. This toolkit pins and restricts the upstream programs; it does not expose every upstream operation. |
| [Didier Stevens: oledump](https://blog.didierstevens.com/programs/oledump-py/) and [olefile API](https://olefile.readthedocs.io/en/latest/Howto.html) | Distinguish upstream stream-content inspection from this repository’s `olefile` directory inventory. |
| [SciPy: Shannon entropy](https://docs.scipy.org/doc/scipy/reference/generated/scipy.stats.entropy.html) | Formula and log base only. The forensic interpretation (why compressed images can be benign) rests on format context, not a classification threshold in SciPy. |
| [Microsoft Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon) and [MITRE ATT&CK T1218](https://attack.mitre.org/techniques/T1218/) | Process event semantics and the proxy-execution technique. Neither alone links an attachment to a host process. |

[Toolkit coverage](Toolkit-and-Evidence.md) links the exact local analysis contracts and pinned versions. The normative sources describe format capabilities; the toolkit has narrower coverage. No source here implies that an arbitrary real document was tested.
