"""Generate inert teaching files; no executable content or Office application needed."""

from __future__ import annotations

import argparse
import struct
from pathlib import Path

FREE, END, FAT = 0xFFFFFFFF, 0xFFFFFFFE, 0xFFFFFFFD
CFB_MAGIC = bytes.fromhex("D0 CF 11 E0 A1 B1 1A E1")


def benign_pdf(indicators: bool = False) -> bytes:
    # /JS occurs in the Keywords text string; it is not a dictionary key or action.
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] >>",
        b"<< /Title (Benign fixture) /Keywords (/JS) >>" if indicators
        else b"<< /Title (Benign fixture) >>",
    ]
    data = bytearray(b"%PDF-1.4\n")
    offsets = []
    for number, obj in enumerate(objects, 1):
        offsets.append(len(data))
        data += f"{number} 0 obj\n".encode() + obj + b"\nendobj\n"
    start = len(data)
    data += b"xref\n0 5\n0000000000 65535 f \n"
    for offset in offsets:
        data += f"{offset:010d} 00000 n \n".encode()
    data += f"trailer\n<< /Size 5 /Root 1 0 R /Info 4 0 R >>\nstartxref\n{start}\n%%EOF\n".encode()
    return bytes(data)


def trailer_fixture(reference: bytes) -> bytes:
    """An inert PDF structural declaration with no active security handler or encrypted bytes."""
    data = bytearray(b"%PDF-1.4\n")
    offsets = []
    for number, body in enumerate((b"<< /Type /Catalog >>", b"<< /Filter /FixtureOnly >>"), 1):
        offsets.append(len(data))
        data.extend(f"{number} 0 obj\n".encode() + body + b"\nendobj\n")
    xref = len(data)
    data.extend(b"xref\n0 3\n0000000000 65535 f \n")
    for offset in offsets:
        data.extend(f"{offset:010d} 00000 n \n".encode())
    return bytes(data) + b"trailer\n<< /Size 3 /Root 1 0 R " + reference + (
        f" >>\nstartxref\n{xref}\n%%EOF\n".encode()
    )


def _entry(name: str, kind: int, *, child: int = FREE, right: int = FREE, color: int = 1) -> bytes:
    row = bytearray(128)
    encoded = (name + "\x00").encode("utf-16le")
    row[:len(encoded)] = encoded
    struct.pack_into("<HBBIII", row, 64, len(encoded), kind, color, FREE, right, child)
    struct.pack_into("<IQ", row, 116, 0 if kind == 1 else END, 0)
    return bytes(row)


def benign_cfb(indicators: bool = False, stream_name: str = "Inventory") -> bytes:
    """Make a 3-sector v3 container with only zero-length streams, never macro code."""
    header = bytearray(512)
    header[:8] = CFB_MAGIC
    struct.pack_into("<5H", header, 24, 0x003E, 3, 0xFFFE, 9, 6)
    struct.pack_into("<9I", header, 40, 0, 1, 1, 0, 4096, END, 0, END, 0)
    struct.pack_into("<109I", header, 76, 0, *([FREE] * 108))
    allocation = struct.pack("<128I", FAT, END, *([FREE] * 126))
    root = _entry("Root Entry", 5, child=1)
    if indicators:
        entries = (
            root + _entry("VBA", 1, child=2, right=3) + _entry("dir", 2)
            + _entry("WordDocument", 2, color=0)
        )
    else:
        entries = root + _entry(stream_name, 2) + bytes(256)
    return bytes(header) + allocation + entries


def metadata_cfb(wrapper: str = "none") -> bytes:
    """Generate plain property data or inert wrapper names; never encrypt anything."""
    header = bytearray(benign_cfb()[:512])
    allocation = struct.pack("<128I", FAT, END, END, END, *([FREE] * 124))
    struct.pack_into("<II", header, 60, 3, 1)  # first MiniFAT sector, count
    root = bytearray(_entry("Root Entry", 5, child=1))
    struct.pack_into("<IQ", root, 116, 2, 128)  # root mini stream
    if wrapper == "none":
        # Property set header, SummaryInformation FMTID and one PID_AUTHOR entry.
        label = b"Fixture author (not evidence of identity)\0"
        value = struct.pack("<II", 30, len(label)) + label
        value += bytes((-len(value)) % 4)
        properties = struct.pack("<HHI16sI", 0xFFFE, 0, 0, bytes(16), 1)
        properties += bytes.fromhex("e0859ff2f94f6810ab9108002b27b3d9") + struct.pack("<I", 48)
        properties += struct.pack("<IIII", 16 + len(value), 1, 4, 16) + value
        row = bytearray(_entry("\x05SummaryInformation", 2))
        struct.pack_into("<IQ", row, 116, 0, len(properties))
        directory = root + row + bytes(256)
        mini = properties.ljust(512, b"\0")
        mini_fat = struct.pack("<128I", 1, END, *([FREE] * 126))
    else:
        if wrapper not in ("empty", "incomplete", "nonempty"):
            raise ValueError("unknown fixture case")
        left = bytearray(_entry("EncryptionInfo", 2, right=FREE if wrapper == "incomplete" else 2))
        right = bytearray(_entry("EncryptedPackage", 2, color=0))
        if wrapper == "nonempty":
            struct.pack_into("<IQ", left, 116, 0, 1)
            struct.pack_into("<IQ", right, 116, 1, 1)
        directory = root + left + (right if wrapper != "incomplete" else bytes(128)) + bytes(128)
        mini = bytes(512)
        mini_fat = struct.pack("<128I", END, END, *([FREE] * 126))
    return bytes(header) + allocation + bytes(directory) + mini + mini_fat


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    directory = parser.parse_args().output
    directory.mkdir(parents=True, exist_ok=True)
    for name, content in {
        "plain.pdf": benign_pdf(), "keyword-only.pdf": benign_pdf(True),
        "plain.cfb": benign_cfb(), "named-only.cfb": benign_cfb(True),
        "properties.cfb": metadata_cfb(), "wrapper-lookalike.docx": metadata_cfb("empty"),
        "reference-only.pdf": trailer_fixture(b"/Encrypt 2 0 R"),
        "unresolved-reference.pdf": trailer_fixture(b"/Encrypt 9 0 R"),
    }.items():
        with (directory / name).open("xb") as file:
            file.write(content)
        print(directory / name)


if __name__ == "__main__":
    main()
