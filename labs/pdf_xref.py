"""Follow a classic PDF xref on generated benign fixtures; not a production parser."""

from __future__ import annotations

import argparse
import re

from .fixtures import benign_pdf


def inspect(data: bytes) -> tuple[int, tuple[int, int], list[tuple[int, int, int]]]:
    if len(data) > 65536 or not data.startswith(b"%PDF-1.4\n"):
        raise ValueError("expected a small PDF 1.4 lab fixture")
    # Read from the end: startxref is the byte offset of the xref keyword.
    tail_start = max(0, len(data) - 1024)
    tail = re.search(rb"\nstartxref\n(\d{1,6})\n%%EOF\n\Z", data[tail_start:])
    if not tail:
        raise ValueError("no supported final startxref")
    xref = int(tail[1])
    if not 9 <= xref < tail_start + tail.start():
        raise ValueError("xref points outside the body")
    lines = data[xref:tail_start + tail.start()].split(b"\n")
    if len(lines) < 4 or lines[0] != b"xref":
        raise ValueError("not a classic xref table")
    subsection = re.fullmatch(rb"0 ([1-9][0-9]{0,2})", lines[1])
    if not subsection:
        raise ValueError("expected one subsection starting at object zero")
    count = int(subsection[1])
    if len(lines) != count + 4 or lines[-2] != b"trailer":
        raise ValueError("unsupported or truncated table")
    objects = []
    for number, line in enumerate(lines[2:-2]):
        record = re.fullmatch(rb"(\d{10}) (\d{5}) ([fn]) ", line)
        if not record:
            raise ValueError("invalid xref entry")
        offset, generation = int(record[1]), int(record[2])
        if record[3] == b"f":
            continue  # A free-list link is not a byte offset to an object.
        label = f"{number} {generation} obj\n".encode("ascii")
        if number == 0 or generation > 65535 or not 9 <= offset < xref or not data.startswith(label, offset, xref):
            raise ValueError("xref does not match object header")
        objects.append((number, generation, offset))
    trailer = re.fullmatch(rb"<< /Size (\d{1,3}) /Root (\d{1,3}) (\d{1,5}) R(?: /Info \d{1,3} \d{1,5} R)? >>", lines[-1])
    if not trailer or int(trailer[1]) != count:
        raise ValueError("unsupported trailer dictionary")
    root = (int(trailer[2]), int(trailer[3]))
    if not any((number, generation) == root for number, generation, _ in objects):
        raise ValueError("trailer Root is missing from the xref")
    return xref, root, objects


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--markers", action="store_true", help="use the harmless metadata marker variant")
    data = benign_pdf(parser.parse_args().markers)
    xref, root, objects = inspect(data)
    print(f"xref @ {xref}; Root = {root[0]} {root[1]} R")
    for number, generation, offset in objects:
        print(f"object {number} {generation} @ {offset}")


if __name__ == "__main__":
    main()
