# PDF triage report

- **Artifact:** SHA-256 and bytes; use a case reference supplied by the analyst if available.
- **Coverage:** For each backend, give tool/version, status, scope, and any reason. Distinguish a failure or partial scan from no matches in a completed scope.
- **Observations:** Cite exact indicator names, counts and the relevant object number/generation where available. Explain when an observation is lexical only. Keep actionability separate from attribution.
- **Assessment:** Give the narrowest defensible interpretation and, when useful, a benign alternative. Do not infer that code executed or that the document is safe.
- **Next step:** Give one defensive action such as keeping the attachment quarantined, checking trusted sender context, or escalating for analyst review. Never ask for an executable payload or fetch a document-specified destination.

## Calibration scenarios

| Toolkit result | Defensible interpretation | Do not say |
| --- | --- | --- |
| Both checks completed with empty observation lists | No supported indicators reported within the scope of these two checks. Compressed object streams and active revisions were not resolved. | The file is safe. |
| PDFiD records `/JS` once and the object check reports it at `4 0` | The name appears lexically and was associated with object `4 0` by the object scanner. It can be benign metadata; neither check establishes an active action. | Object 4 executes JavaScript. |
| PDFiD completed; pdf-parser reports `worker_timeout` | The PDFiD counts can be reported with lexical scope. Object-level coverage is unavailable; keep the file quarantined and hand off the timeout. | There are no suspicious objects. |
| `tool_digest_mismatch` or `sandbox_unavailable` | Report the coverage gap. Ask the operator to restore a reviewed backend or supported isolation. | Bypass the sandbox or use a different script at the same path. |
