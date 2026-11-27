# Metadata, encryption and entropy

[Field book](Home.md) · Depth 3: interpret

| Question | Where to look | What the result supports |
| --- | --- | --- |
| PDF title, author or producer | Classic trailer `/Info` reference, or the corresponding trailer entry in a cross-reference stream. [ISO 32000-1 §14.3.3][pdf] | Document claims, not verified identity or tool provenance. Date strings can be missing or wrong. |
| PDF XML metadata | `/Metadata` stream on the catalog for document-level XMP; other objects can have their own. [ISO §14.3.2][pdf] | Separate from `/Info`; values may disagree. This toolkit does not read XMP. |
| PDF encryption | `/Encrypt` in the applicable trailer entries points to the encryption dictionary. [ISO §7.6][pdf] | A resolved dictionary is a declaration. It does not validate the handler, decide whether an opening password is required, or establish readable plaintext. This toolkit skips Info for its supported encrypted-reference case. |
| Office title, author or related properties | Root `\x05SummaryInformation` and `\x05DocumentSummaryInformation`. [MS-OSHARED §2.3.3][properties] | Typed outer properties. This toolkit reports selected **names and types**, not values, from root SummaryInformation only. |
| Office encrypted wrapper | Outer CFB `EncryptionInfo` and `EncryptedPackage`. [MS-OFFCRYPTO][crypto] | Names and declared sizes are wrapper evidence, not intact ciphertext. Legacy binary Office encryption can be recorded in application structures without the pair. |

**Record gaps separately.** Format identity, encryption declaration, metadata, and payload coverage are different fields. `Unknown`, `unsupported`, and `not inspected` are not synonyms for `absent`. No password is accepted, guessed, stored or tried by this toolkit. Editing restrictions and a requirement to supply credentials to open are different claims.

## Entropy

Shannon byte entropy is `−Σ p(b) log₂ p(b)`, where `p(b)` is the observed fraction of a byte value. Use bits per byte and count only observed values. Repeated `00` scores 0; one copy of each byte from `00` to `FF` in ascending order scores 8 even though the sequence is fully predictable. This measure does not preserve order. [Formula and logarithm base: SciPy entropy reference][entropy].

A high score may describe normal compression (for example, an encoded PDF raster image), encryption, or another dense representation. A whole-file score can hide a smaller region among padding. Small windows cannot represent all values and are not comparable to arbitrarily larger windows. No threshold establishes malware, encryption, or safety. Record the artifact hash, byte count, exact offset and length or stream/object ID, stored versus decoded representation, any window size and stride, and a like-for-like baseline. Entropy is not calculated by the current toolkit.

[pdf]: https://opensource.adobe.com/dc-acrobat-sdk-docs/pdfstandards/PDF32000_2008.pdf
[properties]: https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-oshared/11b56127-35f4-4bfa-a23f-23935a6edf54
[crypto]: https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-offcrypto/7ffe54c5-a76c-4eec-9690-dcc4640aac83
[entropy]: https://docs.scipy.org/doc/scipy/reference/generated/scipy.stats.entropy.html
