"""Bounded classic-PDF metadata walker. Loaded only inside the worker."""

from __future__ import annotations

import re

LIMIT = 128 * 1024
WS = b"\0\t\n\f\r "
TOKEN = re.compile(rb"[\x00\t\n\f\r ]+|%[^\r\n]*|<<|>>|/[^\x00\t\n\f\r ()<>\[\]{}/%]*|[^\x00\t\n\f\r ()<>\[\]{}/%]+|.", re.DOTALL)
TAIL = re.compile(rb"(?:\r\n|\n|\r)startxref[\x00\t\n\f\r ]+([0-9]{1,8})[\x00\t\n\f\r ]+%%EOF[\x00\t\n\f\r ]*\Z")
INITIAL = re.compile(rb"xref[ \t]*(?:\r\n|\n|\r)")
SECTION = re.compile(rb"([0-9]{1,8})[ \t]+([0-9]{1,5})[ \t]*(?:\r\n|\n|\r)")
ROW = re.compile(rb"([0-9]{10}) ([0-9]{5}) ([nf]) ?(?:\r\n|\n|\r)")
REF_NUMBER = re.compile(rb"[0-9]{1,10}\Z")
FIELDS = {b"Title": "title", b"Author": "author", b"Subject": "subject", b"Creator": "creator",
          b"Producer": "producer", b"Keywords": "keywords", b"CreationDate": "creation_date",
          b"ModDate": "modification_date"}


class Unsupported(ValueError):
    """Malformed or outside the restricted metadata grammar."""


def _lex(data: bytes):
    pos = 0
    while pos < len(data):
        match = TOKEN.match(data, pos)
        assert match is not None
        token, pos = match[0], match.end()
        if token[:1] in WS or token.startswith(b"%"):
            continue
        if token == b"(":
            nesting = 1
            while pos < len(data) and nesting:
                char = data[pos]
                pos += 1
                if char == 92:  # Escaped literal character; never decode or export it.
                    pos += 1
                elif char == 40:
                    nesting += 1
                elif char == 41:
                    nesting -= 1
            if nesting:
                raise Unsupported
            yield b"(string)"
        elif token == b"<":
            end = data.find(b">", pos)
            if end == -1 or not re.fullmatch(rb"[0-9a-fA-F\x00\t\n\f\r ]*", data[pos:end]):
                raise Unsupported
            pos = end + 1
            yield b"(string)"
        else:
            yield token


class Parser:
    def __init__(self, data: bytes):
        if len(data) > LIMIT:
            raise Unsupported
        self.tokens = iter(_lex(data))
        self.queue: list[bytes] = []

    def peek(self, n: int = 0) -> bytes:
        while len(self.queue) <= n:
            self.queue.append(next(self.tokens, b""))
        return self.queue[n]

    def take(self) -> bytes:
        token = self.peek()
        return self.queue.pop(0) if token else b""

    def value(self, depth: int = 0):
        if depth > 16:
            raise Unsupported
        token = self.take()
        if token == b"<<":
            result = {}
            while self.peek() != b">>":
                key = self.take()
                if not key.startswith(b"/"):
                    raise Unsupported
                key = re.sub(rb"#([0-9A-Fa-f]{2})", lambda m: bytes([int(m[1], 16)]), key[1:])
                if key in result:
                    raise Unsupported
                result[key] = self.value(depth + 1)
            self.take()
            return result
        if token == b"[":
            while self.peek() != b"]":
                self.value(depth + 1)
            self.take()
            return "array"
        if REF_NUMBER.fullmatch(token):
            if REF_NUMBER.fullmatch(self.peek()) and self.peek(1) == b"R":
                ref = int(token), int(self.take())
                self.take()
                return ref
            return int(token)
        if token == b"(string)":
            return "text"
        if token.startswith(b"/"):
            return re.sub(rb"#([0-9A-Fa-f]{2})", lambda m: bytes([int(m[1], 16)]), token)
        if token in (b"true", b"false", b"null") or re.fullmatch(rb"[+-]?(?:[0-9]+\.?[0-9]*|\.[0-9]+)", token):
            return "scalar"
        raise Unsupported


def _xref(data: bytes):
    base = max(0, len(data) - LIMIT)
    tail = TAIL.search(data[base:])
    if not tail:
        raise Unsupported
    start = int(tail[1])
    if not 8 <= start < base + tail.start() or start < base:
        raise Unsupported
    table = data[start:base + tail.start()]
    header = INITIAL.match(table)
    if not header:
        raise Unsupported
    pos, entries, seen = header.end(), {}, set()
    while (section := SECTION.match(table, pos)) is not None:
        first, count = int(section[1]), int(section[2])
        if not 0 < count <= 4096 - len(seen):
            raise Unsupported
        pos = section.end()
        for number in range(first, first + count):
            row = ROW.match(table, pos)
            if row is None or number in seen:
                raise Unsupported
            seen.add(number)
            pos = row.end()
            offset, generation = int(row[1]), int(row[2])
            if generation > 65535:
                raise Unsupported
            if row[3] == b"n":
                if number == 0 or not 8 <= offset < start:
                    raise Unsupported
                entries[number, generation] = offset
    trailer = Parser(table[pos:])
    if trailer.take() != b"trailer":
        raise Unsupported
    values = trailer.value()
    if not isinstance(values, dict) or trailer.take() or b"Prev" in values or b"XRefStm" in values:
        raise Unsupported
    size = values.get(b"Size")
    if not seen or not isinstance(size, int) or size <= max(seen):
        raise Unsupported
    return values, entries, start


def _dictionary(data: bytes, entries: dict, start: int, ref: object) -> dict:
    if not isinstance(ref, tuple) or ref not in entries:
        raise Unsupported
    offset = entries[ref]
    bounded_end = min(start, offset + LIMIT)
    next_offset = min((value for value in entries.values() if offset < value < bounded_end), default=bounded_end)
    parser = Parser(data[offset:next_offset])
    header = [parser.take() for _ in range(3)]
    if header != [str(ref[0]).encode(), str(ref[1]).encode(), b"obj"]:
        raise Unsupported
    dictionary = parser.value()
    if not isinstance(dictionary, dict) or parser.take() != b"endobj":
        raise Unsupported
    return dictionary


def inspect_metadata(data: bytes) -> dict:
    try:
        trailer, entries, start = _xref(data)
        root = _dictionary(data, entries, start, trailer.get(b"Root"))
        if root.get(b"Type") != b"/Catalog":
            raise Unsupported
    except Unsupported:
        return {"issue": "unsupported_pdf_structure"}
    result = {"catalog_action": b"OpenAction" in root or b"AA" in root}
    if b"Encrypt" in trailer:
        try:
            _dictionary(data, entries, start, trailer[b"Encrypt"])
        except Unsupported:
            return {**result, "issue": "unresolved_pdf_encryption_reference"}
        return {**result, "encryption": "dictionary_referenced"}
    result["encryption"] = "not_indicated"
    if b"Info" not in trailer:
        return {**result, "fields": []}
    try:
        info = _dictionary(data, entries, start, trailer[b"Info"])
    except Unsupported:
        return {**result, "issue": "unresolved_pdf_info_reference"}
    return {**result, "fields": [
        {"name": label, "kind": "text" if info[key] == "text" else "unexpected_type"}
        for key, label in FIELDS.items() if key in info
    ]}
