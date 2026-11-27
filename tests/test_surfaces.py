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

from forensic_maldoc import triage_pdf
from forensic_maldoc.sandbox import run_worker
from forensic_maldoc.triage import TOOLS, _load_script
from forensic_maldoc.worker import inspect
from labs.fixtures import benign_pdf


class Surfaces(unittest.IsolatedAsyncioTestCase):
    @unittest.skipUnless(importlib.util.find_spec("mcp"), "install the mcp extra")
    async def test_stdio_tool_matches_cli_and_python(self):
        from mcp import Client, StdioServerParameters

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            real_tools = os.getenv("FORENSIC_MALDOC_TEST_TOOLS") if os.getenv("FORENSIC_MALDOC_TEST_ISOLATION") else None
            tools_root = Path(real_tools).resolve() if real_tools else root
            (root / "test.pdf").write_bytes(benign_pdf(bool(real_tools)))
            flags = ["--staging", tmp, "--tools", str(tools_root)]
            python_result = asdict(await asyncio.to_thread(triage_pdf, root, "test.pdf", tools_root))
            cli = await asyncio.to_thread(
                subprocess.run,
                [sys.executable, "-m", "forensic_maldoc.cli", "scan", *flags, "test.pdf"],
                capture_output=True, check=False, text=True, timeout=10,
            )
            self.assertEqual(cli.returncode, 0 if real_tools else 1)
            self.assertEqual(json.loads(cli.stdout), python_result)
            server = StdioServerParameters(
                command=sys.executable, args=["-m", "forensic_maldoc.cli", "mcp", *flags],
            )
            async with Client(server) as client:
                tools = (await client.list_tools()).tools
                self.assertEqual({tool.name for tool in tools}, {
                    "triage_staged_pdf", "triage_staged_ole", "assess_staged_document",
                })
                for tool in tools:
                    self.assertEqual(list(tool.input_schema["properties"]), ["basename"])
                    self.assertIsNotNone(tool.output_schema)
                result = await client.call_tool("triage_staged_pdf", {"basename": "test.pdf"})
                self.assertFalse(result.is_error)
                self.assertEqual(result.structured_content, python_result)
                denied = await client.call_tool("triage_staged_pdf", {"basename": "../test.pdf"})
                self.assertTrue(denied.is_error)
                self.assertIsNone(denied.structured_content)


@unittest.skipUnless(os.getenv("FORENSIC_MALDOC_TEST_TOOLS"), "set the path to verified upstream scripts")
class RealTools(unittest.TestCase):
    def setUp(self):
        self.tools = Path(os.environ["FORENSIC_MALDOC_TEST_TOOLS"])

    def test_upstream_adapters_against_inert_fixtures(self):
        for tool in TOOLS:
            _load_script(self.tools, tool)
        with tempfile.TemporaryDirectory() as tmp:
            sample = Path(tmp) / "fixture.pdf"
            for indicators in (False, True):
                sample.write_bytes(benign_pdf(indicators))
                for tool in TOOLS:
                    with self.subTest(tool=tool.name, indicators=indicators):
                        result = inspect(tool.name, self.tools / tool.filename, sample, tool.indicators, 200)
                        self.assertIsNone(result.get("partial_reason"))
                        rows = result["observations"]
                        if not indicators:
                            self.assertEqual(rows, [])
                        elif tool.name == "pdfid":
                            self.assertIn({"indicator": "/JS", "count": 1, "obfuscated": 0}, rows)
                        else:
                            self.assertIn({"indicator": "/JS", "object_number": 4, "generation": 0}, rows)
            sample.write_bytes(benign_pdf().rsplit(b"%%EOF", 1)[0])
            tool = TOOLS[1]
            incomplete = inspect(tool.name, self.tools / tool.filename, sample, tool.indicators, 200)
            self.assertEqual(incomplete.get("partial_reason"), "structure_incomplete")

    @unittest.skipUnless(os.getenv("FORENSIC_MALDOC_TEST_ISOLATION"), "requires namespace support")
    def test_sandboxed_analyzers_complete(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "fixture.pdf").write_bytes(benign_pdf(True))
            report = triage_pdf(root, "fixture.pdf", self.tools)
            self.assertEqual([(c.tool, c.status, c.reason) for c in report.checks], [
                ("pdfid", "completed", None), ("pdf-parser", "completed", None),
            ])
            self.assertEqual(report.checks[0].observations[0].indicator, "/JS")

    @unittest.skipUnless(os.getenv("FORENSIC_MALDOC_TEST_ISOLATION"), "requires namespace support")
    def test_worker_cannot_read_unstaged_file_or_see_host_network(self):
        with tempfile.TemporaryDirectory() as tmp:
            sentinel = Path(tmp) / "unstaged"
            sentinel.write_text("not exposed")
            diagnostic = f'''\
from pathlib import Path
from socket import if_nameindex
from xml.dom.minidom import parseString

def PDFiD(*args, **kwargs):
    assert not Path({str(sentinel)!r}).exists()
    assert all(name == "lo" for _, name in if_nameindex())
    assert Path("/sample.pdf").read_bytes().startswith(b"%PDF-")
    return parseString('<PDFiD ErrorOccured="False" IsPDF="True"><Keyword Name="/JS" Count="1" HexcodeCount="0"/></PDFiD>')
'''.encode()
            result = run_worker("pdfid", ("/JS",), 2, diagnostic, benign_pdf())
            self.assertEqual(result["observations"], [{"indicator": "/JS", "count": 1, "obfuscated": 0}])
