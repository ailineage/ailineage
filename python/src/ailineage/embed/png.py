# SPDX-License-Identifier: Apache-2.0
"""PNG: iTXt chunk with keyword `ailineage` (SPEC §5.2)."""

from __future__ import annotations

import struct
import zlib

SIG = b"\x89PNG\r\n\x1a\n"
KEYWORD = b"ailineage"


def is_png(b: bytes) -> bool:
    return b[:8] == SIG


def chunks(b: bytes):
    if not is_png(b):
        raise ValueError("not a PNG")
    i = 8
    while i < len(b):
        if i + 12 > len(b):
            raise ValueError("truncated PNG chunk at %d" % i)
        (n,) = struct.unpack(">I", b[i:i + 4])
        if i + 12 + n > len(b):
            raise ValueError("truncated PNG chunk at %d" % i)
        yield i, i + 12 + n, b[i + 4:i + 8], b[i + 8:i + 8 + n]
        i += 12 + n


def _is_ours(ctype: bytes, data: bytes) -> bool:
    return ctype == b"iTXt" and data.split(b"\x00", 1)[0] == KEYWORD


def _text(data: bytes) -> bytes:
    # keyword NUL comp_flag comp_method lang NUL translated NUL text
    rest = data[len(KEYWORD) + 1:]
    if rest[:2] != b"\x00\x00":
        raise ValueError("ailineage iTXt chunk must be uncompressed (REQ-0211)")
    lang, _, rest = rest[2:].partition(b"\x00")
    tr, _, text = rest.partition(b"\x00")
    if lang or tr:
        raise ValueError("ailineage iTXt chunk must have empty language and translation")
    return text


def extract(b: bytes) -> list[bytes]:
    return [_text(d) for _, _, t, d in chunks(b) if _is_ours(t, d)]


def strip(b: bytes) -> bytes:
    out = bytearray(SIG)
    for s, e, t, d in chunks(b):
        if not _is_ours(t, d):
            out += b[s:e]
    return bytes(out)


def _chunk(ctype: bytes, data: bytes) -> bytes:
    return struct.pack(">I", len(data)) + ctype + data + \
        struct.pack(">I", zlib.crc32(ctype + data) & 0xFFFFFFFF)


def embed(b: bytes, manifest_json: bytes) -> bytes:
    """Replace any existing manifest; insert the chunk immediately before IEND (REQ-0212)."""
    b = strip(b)
    data = KEYWORD + b"\x00" + b"\x00\x00" + b"\x00" + b"\x00" + manifest_json
    out = bytearray(SIG)
    for s, e, t, _ in chunks(b):
        if t == b"IEND":
            out += _chunk(b"iTXt", data)
        out += b[s:e]
    return bytes(out)
