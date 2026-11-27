"""Walk a classic CFB directory on generated benign fixtures; never open a stream."""

from __future__ import annotations

import argparse
import struct
from dataclasses import dataclass

from .fixtures import CFB_MAGIC, END, FAT, FREE, benign_cfb

SECTOR = 512
ROW = 128


@dataclass(frozen=True)
class Entry:
    sid: int
    path: tuple[str, ...]
    kind: int
    size: int


def inspect(data: bytes) -> tuple[list[int], list[Entry]]:
    if not 3 * SECTOR <= len(data) <= 128 * SECTOR or len(data) % SECTOR:
        raise ValueError("expected a small sector-aligned lab fixture")
    if data[:8] != CFB_MAGIC or struct.unpack_from("<4H", data, 26) != (3, 0xFFFE, 9, 6):
        raise ValueError("expected a little-endian CFB v3 header")
    _, fats, first_dir, _, _, _, _, _, difats = struct.unpack_from("<9I", data, 40)
    if fats != 1 or difats != 0:
        raise ValueError("expected one header-listed FAT sector and no extended DIFAT")
    fat_id = struct.unpack_from("<I", data, 76)[0]
    sector_count = len(data) // SECTOR - 1

    def sector(number: int) -> bytes:
        if not 0 <= number < sector_count:
            raise ValueError("sector outside fixture")
        offset = (number + 1) * SECTOR
        return data[offset:offset + SECTOR]

    fat = struct.unpack("<128I", sector(fat_id))
    if fat[fat_id] != FAT:
        raise ValueError("FAT sector is not marked FATSECT")
    chain: list[int] = []
    seen_sectors: set[int] = set()
    parts = []
    current = first_dir
    while current != END:
        if current in seen_sectors or current == fat_id:
            raise ValueError("invalid directory sector chain")
        parts.append(sector(current))  # Reject out-of-range IDs before indexing the FAT.
        chain.append(current)
        seen_sectors.add(current)
        current = fat[current]
    directory = b"".join(parts)

    def entry(sid: int) -> tuple[str, int, int, int, int, int]:
        if not 0 <= sid < len(directory) // ROW:
            raise ValueError("directory ID outside chain")
        row = directory[sid * ROW:(sid + 1) * ROW]
        length, kind, _, left, right, child = struct.unpack_from("<HBBIII", row, 64)
        if kind not in (1, 2, 5) or not 2 <= length <= 64 or length % 2:
            raise ValueError("invalid live directory entry")
        if row[length - 2:length] != b"\0\0":
            raise ValueError("unterminated directory name")
        name = row[:length - 2].decode("utf-16le")
        size = struct.unpack_from("<Q", row, 120)[0]
        return name, kind, left, right, child, size

    root_name, root_kind, left, right, child, root_size = entry(0)
    if root_kind != 5 or left != FREE or right != FREE:
        raise ValueError("invalid root entry")
    rows = [Entry(0, (root_name,), root_kind, root_size)]
    pending = [(child, (root_name,))]
    seen_entries = {0}
    while pending:
        sid, parent = pending.pop()
        if sid == FREE:
            continue
        if sid in seen_entries or len(parent) > 64:
            raise ValueError("invalid directory tree or depth")
        seen_entries.add(sid)
        name, kind, left, right, child, size = entry(sid)
        path = (*parent, name)
        if kind == 5 or (kind == 2 and child != FREE):
            raise ValueError("unexpected root or stream child")
        rows.append(Entry(sid, path, kind, size))
        pending.extend(((right, parent), (left, parent), (child, path)))
    return chain, rows


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--markers", action="store_true", help="use the directory marker variant")
    chain, rows = inspect(benign_cfb(parser.parse_args().markers))
    print(f"Directory sectors: {chain}")
    kinds = {1: "storage", 2: "stream", 5: "root"}
    for entry in rows:
        print(f"SID {entry.sid} {kinds[entry.kind]}: {'/'.join(entry.path)}; declared size={entry.size}")


if __name__ == "__main__":
    main()
