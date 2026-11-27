import struct
import unittest

from labs import cfb_directory, pdf_xref
from labs.fixtures import benign_cfb, benign_pdf


class ParserLabs(unittest.TestCase):
    def test_pdf_offsets_and_root(self):
        xref, root, rows = pdf_xref.inspect(benign_pdf(True))
        self.assertEqual((xref, root), (247, (1, 0)))
        self.assertEqual(rows, [(1, 0, 9), (2, 0, 58), (3, 0, 115), (4, 0, 186)])

    def test_pdf_rejects_wrong_xref_target(self):
        bad = benign_pdf().replace(b"0000000009 00000 n", b"0000000010 00000 n")
        with self.assertRaisesRegex(ValueError, "xref does not match"):
            pdf_xref.inspect(bad)

    def test_cfb_resolves_siblings_and_children(self):
        chain, rows = cfb_directory.inspect(benign_cfb(True))
        self.assertEqual(chain, [1])
        self.assertEqual([row.path for row in rows], [
            ("Root Entry",), ("Root Entry", "VBA"),
            ("Root Entry", "VBA", "dir"), ("Root Entry", "WordDocument"),
        ])

    def test_cfb_rejects_cyclic_sector_chain(self):
        bad = bytearray(benign_cfb())
        struct.pack_into("<I", bad, 512 + 4, 1)
        with self.assertRaisesRegex(ValueError, "invalid directory sector chain"):
            cfb_directory.inspect(bytes(bad))
