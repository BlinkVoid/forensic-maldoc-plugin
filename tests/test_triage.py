from __future__ import annotations

import hashlib
import tempfile
import unittest
from dataclasses import asdict
from pathlib import Path
from unittest.mock import patch

from forensic_maldoc import triage_pdf
from labs.fixtures import benign_pdf


class TriageContract(unittest.TestCase):
    def test_reports_same_snapshot_for_both_checks(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            fixture = benign_pdf()
            (root / "note.pdf").write_bytes(fixture)
            with (
                patch("forensic_maldoc.triage._load_script", return_value=b"pinned", create=True),
                patch("forensic_maldoc.triage._run_worker", create=True) as runner,
            ):
                runner.side_effect = [
                    {"observations": [{"indicator": "/JS", "count": 2, "obfuscated": 1}]},
                    {"observations": [{"indicator": "/JS", "object_number": 4, "generation": 0}]},
                ]
                report = asdict(triage_pdf(root, "note.pdf", root))
            self.assertEqual(report["schema_version"], 1)
            self.assertEqual(report["sha256"], hashlib.sha256(fixture).hexdigest())
            self.assertEqual(report["size_bytes"], len(fixture))
            self.assertEqual([c["status"] for c in report["checks"]], ["completed", "completed"])
            self.assertEqual(report["checks"][0]["observations"][0]["count"], 2)
            self.assertEqual(report["checks"][1]["observations"][0]["object_number"], 4)
            self.assertEqual([c.args[-1] for c in runner.call_args_list], [fixture, fixture])
            self.assertEqual((root / "note.pdf").read_bytes(), fixture)

    def test_input_rejects_path_escape_symlinks_special_and_wrong_type(self):
        with tempfile.TemporaryDirectory() as tmp:
            import os

            root = Path(tmp)
            (root / "note.pdf").write_bytes(benign_pdf())
            (root / "alias.pdf").symlink_to(root / "note.pdf")
            (root / "text.pdf").write_text("not PDF")
            os.mkfifo(root / "pipe.pdf")
            for name in ("../note.pdf", "./note.pdf", "https://host/note.pdf", "alias.pdf", "pipe.pdf", "text.pdf"):
                with self.subTest(name=name), self.assertRaises(ValueError):
                    triage_pdf(root, name, root)

    def test_tools_missing_or_changed_do_not_run_or_claim_absence(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "note.pdf").write_bytes(benign_pdf())
            (root / "pdfid.py").write_text("raise Exception('not pinned')")
            with patch("forensic_maldoc.triage._run_worker", create=True) as runner:
                checks = asdict(triage_pdf(root, "note.pdf", root))["checks"]
            runner.assert_not_called()
            self.assertEqual([c["status"] for c in checks], ["not_checked", "not_checked"])
            self.assertEqual([c["reason"] for c in checks], ["tool_digest_mismatch", "tool_unavailable"])


if __name__ == "__main__":
    unittest.main()
