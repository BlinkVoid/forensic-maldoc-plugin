from __future__ import annotations

import asyncio
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from dataclasses import asdict
from pathlib import Path

from labs.fixtures import benign_pdf, metadata_cfb, trailer_fixture


class Assessment(unittest.IsolatedAsyncioTestCase):
    def scan(self, root: Path, name: str, content: bytes):
        (root / name).write_bytes(content)
        return subprocess.run(
            [sys.executable, "-m", "forensic_maldoc.cli", "assess", "--staging", str(root), name],
            capture_output=True, text=True, check=False, timeout=12,
        )

    async def test_zip_signature_is_not_automatically_ooxml(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = await asyncio.to_thread(self.scan, Path(tmp), "outer.docx", b"PK\x03\x04")
            self.assertEqual(result.returncode, 1, result.stderr)
            data = json.loads(result.stdout)
            self.assertEqual((data["format"], data["encryption"]["state"]), ("zip_signature", "unknown"))
            self.assertEqual(data["findings"], [])

    @unittest.skipUnless(os.getenv("FORENSIC_MALDOC_TEST_ISOLATION"), "requires namespace support")
    async def test_metadata_rules_and_real_transport_parity(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            plain = benign_pdf().replace(b"Benign fixture", b"/Encrypt!!!!!!")
            result = await asyncio.to_thread(self.scan, root, "invoice.doc", plain)
            self.assertEqual(result.returncode, 0, result.stderr or result.stdout)
            data = json.loads(result.stdout)
            self.assertEqual((data["format"], data["encryption"]["state"]), ("pdf", "not_indicated"))
            self.assertEqual(data["metadata"]["fields"], [{"name": "title", "kind": "text"}])
            self.assertNotIn("/Encrypt!!!!!!", result.stdout)
            self.assertEqual([f["rule_id"] for f in data["findings"]], ["extension_mismatch"])
            linked = await asyncio.to_thread(self.scan, root, "link.pdf", trailer_fixture(b"/Encrypt 2 0 R"))
            self.assertEqual(linked.returncode, 0, linked.stderr or linked.stdout)
            self.assertEqual(json.loads(linked.stdout)["encryption"]["state"], "dictionary_referenced")
            broken = await asyncio.to_thread(self.scan, root, "broken.pdf", trailer_fixture(b"/Encrypt 9 0 R"))
            self.assertEqual(broken.returncode, 1, broken.stderr or broken.stdout)
            self.assertEqual(json.loads(broken.stdout)["encryption"]["state"], "unknown")
            from forensic_maldoc import assess_document

            actual = asdict(await asyncio.to_thread(assess_document, root, "invoice.doc"))
            self.assertEqual(actual, data)
            if importlib.util.find_spec("mcp"):
                from mcp import Client, StdioServerParameters

                server = StdioServerParameters(command=sys.executable, args=[
                    "-m", "forensic_maldoc.cli", "mcp", "--staging", tmp,
                ])
                async with Client(server) as client:
                    response = await client.call_tool("assess_staged_document", {"basename": "invoice.doc"})
                    self.assertFalse(response.is_error)
                    self.assertEqual(response.structured_content, data)

    @unittest.skipUnless(os.getenv("FORENSIC_MALDOC_TEST_ISOLATION"), "requires namespace support")
    async def test_unsupported_pdf_and_wrong_type_are_not_clean_results(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            partial = await asyncio.to_thread(self.scan, root, "update.pdf", trailer_fixture(b"/Prev 9"))
            self.assertEqual(partial.returncode, 1)
            data = json.loads(partial.stdout)
            self.assertEqual(data["metadata"]["reason"], "unsupported_pdf_structure")
            self.assertEqual(data["encryption"]["state"], "unknown")
            altered = benign_pdf().replace(b"(Benign fixture)", b"123             ")
            anomaly = await asyncio.to_thread(self.scan, root, "type.pdf", altered)
            self.assertEqual(anomaly.returncode, 0, anomaly.stdout or anomaly.stderr)
            self.assertEqual(json.loads(anomaly.stdout)["findings"][0]["rule_id"], "metadata_unexpected_type")

    @unittest.skipUnless(os.getenv("FORENSIC_MALDOC_TEST_ISOLATION"), "requires namespace support")
    async def test_ole_metadata_and_wrapper_coverage(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for name, case, expected in (
                ("props.cfb", "none", "unknown"),
                ("empty.docx", "empty", "office_wrapper_empty"),
                ("incomplete.docx", "incomplete", "office_wrapper_incomplete"),
                ("pair.docx", "nonempty", "office_wrapper_indicated"),
            ):
                result = await asyncio.to_thread(self.scan, root, name, metadata_cfb(case))
                self.assertEqual(result.returncode, 0, result.stderr or result.stdout)
                data = json.loads(result.stdout)
                self.assertEqual(data["encryption"]["state"], expected)
                self.assertEqual(data["payload_status"], "not_inspected")
                self.assertNotIn("Fixture author", result.stdout)
                if case == "none":
                    self.assertEqual(data["metadata"]["fields"], [{"name": "author", "kind": "text"}])
                else:
                    self.assertEqual([finding["rule_id"] for finding in data["findings"]], [expected])
