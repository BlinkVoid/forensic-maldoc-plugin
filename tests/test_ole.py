from __future__ import annotations

import asyncio
import hashlib
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from labs.fixtures import benign_cfb, benign_pdf


@unittest.skipUnless(os.getenv("FORENSIC_MALDOC_TEST_ISOLATION"), "requires namespace support")
class OleSurfaces(unittest.IsolatedAsyncioTestCase):
    def _cli(self, root: Path, name: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, "-m", "forensic_maldoc.cli", "ole", "--staging", str(root), name],
            capture_output=True, check=False, text=True, timeout=12,
        )

    async def test_inventory_reports_known_names_without_a_macro_verdict(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            data = benign_cfb(True)
            (root / "shapes.doc").write_bytes(data)
            cli = await asyncio.to_thread(self._cli, root, "shapes.doc")
            self.assertEqual(cli.returncode, 0, cli.stderr or cli.stdout)
            result = json.loads(cli.stdout)
            self.assertEqual(result["sha256"], hashlib.sha256(data).hexdigest())
            check = result["checks"][0]
            self.assertEqual(check["status"], "completed")
            self.assertEqual(check["stream_count"], 2)
            self.assertEqual({row["indicator"] for row in check["entries"]},
                             {"vba_storage", "vba_dir_name", "word_document_name"})
            self.assertEqual({row["declared_size"] for row in check["entries"] if row["kind"] == "stream"}, {0})

            from dataclasses import asdict

            from forensic_maldoc import triage_ole

            self.assertEqual(asdict(await asyncio.to_thread(triage_ole, root, "shapes.doc")), result)
            if importlib.util.find_spec("mcp"):
                from mcp import Client, StdioServerParameters

                server = StdioServerParameters(command=sys.executable, args=[
                    "-m", "forensic_maldoc.cli", "mcp", "--staging", tmp,
                ])
                async with Client(server) as client:
                    response = await client.call_tool("triage_staged_ole", {"basename": "shapes.doc"})
                    self.assertFalse(response.is_error)
                    self.assertEqual(response.structured_content, result)
                    refused = await client.call_tool("triage_staged_ole", {"basename": "../shapes.doc"})
                    self.assertTrue(refused.is_error)

    async def test_intake_failure_and_opaque_unknown_names(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "wrong.doc").write_bytes(benign_pdf())
            (root / "broken.cfb").write_bytes(benign_cfb()[:600])
            (root / "plain.cfb").write_bytes(benign_cfb(stream_name="untrusted-message"))
            (root / "link.cfb").symlink_to(root / "plain.cfb")
            for rejected in ("wrong.doc", "../plain.cfb", "link.cfb"):
                self.assertEqual((await asyncio.to_thread(self._cli, root, rejected)).returncode, 2)
            broken = await asyncio.to_thread(self._cli, root, "broken.cfb")
            self.assertNotEqual(broken.returncode, 0)
            data = await asyncio.to_thread(self._cli, root, "plain.cfb")
            self.assertEqual(data.returncode, 0, data.stdout or data.stderr)
            self.assertNotIn("untrusted-message", data.stdout)
            entries = json.loads(data.stdout)["checks"][0]["entries"]
            self.assertEqual(len(entries), 1)
            self.assertIsNone(entries[0]["indicator"])
            self.assertRegex(entries[0]["path_sha256"], r"^[0-9a-f]{64}$")
