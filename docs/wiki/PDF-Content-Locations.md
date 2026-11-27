# PDF content locations: images, JavaScript, forms and attachments

[Field book](Home.md) · Depth 2: navigate · [PDF object structure](PDF-Structure.md)

The paths below are logical references relative to the current catalog or page, not fixed file offsets. Resolve inherited resources and indirect objects when the parser supports them. The section numbers refer to [ISO 32000-1:2008][pdf].

## Page graphics, images and text

| Looking for | Usual location | What to record | Source |
| --- | --- | --- | --- |
| Page instructions | `/Root → /Pages → /Kids → Page → /Contents`; a stream or ordered array of streams | Page number, page object, content stream IDs. Contents contains drawing instructions; it is not necessarily a plain text transcript. | §§7.7.3, 7.8.2 |
| Raster image XObject (external to the content stream) | Page `/Resources → /XObject → resource name → /Subtype /Image`. The drawing stream refers to the named XObject with `Do`; `/Resources` can be inherited from a page-tree node. | Resource name, image object ID, width, height, colour space, and filter. A resource entry does not prove it was drawn. | §§7.7.3.4, 7.8.3, 8.9.1, 8.9.5 |
| Nested graphics or images | A `Do` can refer to `/Subtype /Form` rather than `/Image`. A Form XObject can contain its own instructions and resource dictionary. | Form object ID and nested resource path. A Form XObject is reusable graphics, not an AcroForm field. | §§8.9, 8.10 |
| Inline raster image | In a page or Form XObject content stream between the `BI`, `ID`, `EI` operators. It has no standalone indirect image object. | Content stream ID and decoded-stream location if available. An XObject-only count misses it. | §8.9.7 |
| Thumbnail or annotation art | Page `/Thumb`; annotation `/AP` appearance dictionary/stream. Separate from the ordinary page contents. | Which thumbnail or appearance object was inspected. A thumbnail is not page content. | §§12.3.4, 12.5.5 |
| Text and fonts | Content-stream text operators and font resources under `/Resources → /Font`. Font encodings and `/ToUnicode` can affect text recovery; a scan may only have image pixels. | Whether the observation was a raw byte string, decoded glyph text, or OCR output. | §§9.3–9.10 |

## Interactive elements and embedded data

| Looking for | Usual location | What it means | Source |
| --- | --- | --- | --- |
| Open-time entry | Catalog `/OpenAction` | A destination array (for example, a page view) or an action dictionary; the key name does not identify JavaScript. | §7.7.2, Table 28 |
| Document JavaScript | Catalog `/Names → /JavaScript` name tree. The leaves map names to JavaScript actions. | A document-level script declaration, distinct from page content. Reader support and policy are not established by the file. | §§7.7.4, 7.9.6, 12.6.4.16 |
| JavaScript action | In an action dictionary, `/S /JavaScript` identifies the action type; `/JS` stores a text string or a text stream. | Cite the object and association with its owner or event. A `/JS` token in metadata or a detached object is materially different. Do not execute it. | §12.6.4.16, Table 217 |
| Event-bound actions | `/AA` additional-actions on catalog, page, annotation/widget or field where defined; annotation/outline actions may be at `/A`. | Identify the owner and event key. The same key spelling in an unrelated dictionary proves nothing. Link annotations may instead contain a destination. | §§12.3.3, 12.5.6.5, 12.6.2–12.6.3 |
| Interactive forms | Catalog `/AcroForm → /Fields`, child fields via `/Kids`, and `/Widget` annotations (sometimes combined with the field dictionary). XFA is a separate entry in the form dictionary in PDF 1.7. | Distinguish field values, widget appearance, and declared actions. A form or `/XFA` spelling does not prove JavaScript. | §§12.5.6.19, 12.7.2–12.7.3, 12.7.8 |
| Document attachment | Catalog `/Names → /EmbeddedFiles` name tree or a `/FileAttachment` annotation → `/FS`; a file-specification dictionary can reference embedded stream data through `/EF`. | Keep the discovery path, file-specification ID and embedded stream ID separate. A shown filename does not validate contents; an external file reference is not an embedded file. | §§7.7.4, 7.11.3–7.11.4, 12.5.6.15 |

**Evidence levels:** lexical hit → name in an identified object → typed entry resolved from the current graph → behavior in a particular reader or host. The toolkit reports the first two levels for selected PDF indicators; it does not inventory images, walk the complete action graph, decode payload streams, or observe execution. See [tool coverage](Toolkit-and-Evidence.md).

[pdf]: https://opensource.adobe.com/dc-acrobat-sdk-docs/pdfstandards/PDF32000_2008.pdf
