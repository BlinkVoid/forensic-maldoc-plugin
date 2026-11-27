---
name: maldoc-evidence-review
description: Review a malicious-document triage report before handoff, checking artifact identity, observation references, coverage gaps, and whether conclusions overstate the evidence.
---

# Review a document investigation

Use the exact artifact report for the stated SHA-256. A summary or unverified screenshot is not a substitute. Review the draft against these decisions:

- **Identity:** The artifact hash and byte count are present and match the report. Do not merge observations from other revisions or different hashes.
- **Evidence:** Each factual claim points to a check, version, and reported indicator. A lexical hit supports a statement about a name/count; an object hit supports a statement about a name associated with an object number/generation. For OLE, cite the fixed indicator or opaque directory-path hash and distinguish a declared size from verified bytes. None of these observations proves an action or execution.
- **Coverage:** Reject broad negative conclusions from missing, failed, or partial checks. For completed checks, state the specific scope and retain the documented gaps. Top-level PDF scanning does not settle compressed objects or active revisions. A trailer encryption reference is not an opening-password test, and CFB wrapper entries do not verify encrypted stream contents. Keep container, metadata, and payload coverage separate.
- **Context checks:** If citing entropy, require the measured byte range or stream and distinguish compression from unproven encryption. If citing a LOLBin, distinguish a string hit, an actual process event, and evidence linking that event to the document. An executable name or a valid signature does not settle intent.
- **Handoff:** Ask for one defensive next step that does not open the sample, fetch links, or bypass sandboxing. Separate observed facts, hypotheses, and actions.

Return one disposition: **supported within stated scope**, **revise the wording** (identify the unsupported claims), or **insufficient evidence** (identify the missing report or check). Do not perform another analysis or retrieve an original sample simply to review a draft.
