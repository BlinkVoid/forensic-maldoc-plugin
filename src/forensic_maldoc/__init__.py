"""Read-only PDF and OLE/CFB triage."""

from .assessment import assess_document
from .ole import triage_ole
from .triage import triage_pdf

__all__ = ["assess_document", "triage_ole", "triage_pdf"]
