# PDF file structure and cross-references

[Field book](Home.md) · Depth 2: navigate · [Magic bytes](File-Signatures.md) · [Content locations](PDF-Content-Locations.md)

## Physical layout

```text
start of file
    %PDF-1.7            header
    indirect objects    dictionaries, streams, and other values
    xref                classic cross-reference rows, OR a cross-reference stream object
    trailer             dictionary after a classic table; keys live in an xref stream dictionary otherwise
    startxref           keyword, then the byte offset of the current cross-reference section
    %%EOF               end marker for this revision
```

A later save can append objects and another cross-reference section and trailer. The old bytes and `%%EOF` often remain. Begin with the last conforming `startxref`; the value is an offset from the start of the file, not an object number. In a classic section `/Prev` links to the preceding cross-reference section, and in a hybrid-reference file `/XRefStm` points to a companion cross-reference stream. Merging revisions requires understanding both replaced and freed entries; scanning in physical order is not equivalent. See [ISO 32000-1 §§7.5.4–7.5.8][pdf].

## Terms and where to look

| Syntax or key | Interpretation |
| --- | --- |
| `4 0 obj` … `endobj`; `4 0 R` | An indirect object definition and its reference: object number 4, generation 0. Resolve the reference through the applicable xref records and verify the target identity. |
| `<< … >>`, `[ … ]`, `/Name`, `(text)` | Dictionary, array, name and literal string. `(/JS)` is text, not the dictionary key `/JS`. See §7.3. |
| `stream` … `endstream` | An indirect stream object has a dictionary and a byte sequence. Inspect `/Length`, `/Filter`, and `/DecodeParms` in context; length may be indirect. The stored data need not be text. See §§7.3.8, 7.4. |
| Classic xref table | Subsections identify the starting object number and row count. In-use rows encode byte offset and generation; free rows are not byte offsets. See §7.5.4. |
| Cross-reference stream, `/Type /XRef` | Binary index rows described by `/W` and `/Index`; keys that would appear in a classic trailer are part of the stream dictionary. Entries can point to an object-stream number and an index rather than a physical offset. See §7.5.8. |
| Object stream, `/Type /ObjStm` | Stream holding multiple non-stream indirect objects. An object inside it has no separate on-disk `obj` header. Don't confuse this container with the cross-reference stream. See §7.5.7. |
| `/Root`, `/Info`, `/Encrypt` | Catalog reference, optional document information dictionary, and optional encryption dictionary respectively. Only the catalog is the root of the document object graph. See §§7.5.5, 7.6, 7.7.2. |

## Logical layout

```text
active trailer /Root -> document catalog
                         |-- /Pages -> page tree /Kids -> page dictionaries
                         |                 |-- /Contents and /Resources
                         |                 `-- /Annots
                         |-- /AcroForm
                         `-- /Names
```

The catalog can also declare a version newer than the header in a supported incremental update. Record the header version and the catalog version separately if observed (§7.5.2, §7.7.2). The toolkit’s metadata walker only follows supported classic xref/trailer references; a top-level token or object scan is not active revision reconstruction.

[pdf]: https://opensource.adobe.com/dc-acrobat-sdk-docs/pdfstandards/PDF32000_2008.pdf
