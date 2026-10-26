# SPDX-License-Identifier: Apache-2.0
"""WebP: top-level RIFF chunk `AILN` in the extended format (SPEC §5.4)."""

from __future__ import annotations

import struct

FOURCC = b"AILN"


def is_webp(b: bytes) -> bool:
    return b[:4] == b"RIFF" and b[8:12] == b"WEBP"


def chunks(b: bytes):
    if not is_webp(b):
        raise ValueError("not a WebP")
    (riff,) = struct.unpack("<I", b[4:8])
    end = min(len(b), 8 + riff)
    i = 12
    while i < end:
        if i + 8 > end:
            raise ValueError("truncated RIFF chunk at %d" % i)
        (n,) = struct.unpack("<I", b[i + 4:i + 8])
        e = i + 8 + n + (n & 1)
        if i + 8 + n > end:
            raise ValueError("truncated RIFF chunk at %d" % i)
        yield i, min(e, end), b[i:i + 4]
        i = e


def _build(body: bytes) -> bytes:
    return b"RIFF" + struct.pack("<I", 4 + len(body)) + b"WEBP" + body


def extract(b: bytes) -> list[bytes]:
    out = []
    for s, _, c in chunks(b):
        if c == FOURCC:
            (n,) = struct.unpack("<I", b[s + 4:s + 8])
            out.append(b[s + 8:s + 8 + n])
    return out


def strip(b: bytes) -> bytes:
    return _build(b"".join(b[s:e] for s, e, c in chunks(b) if c != FOURCC))


def extend(b: bytes) -> bytes:
    """Convert a simple-format WebP to the extended format by inserting VP8X (REQ-0226)."""
    cs = list(chunks(b))
    if cs[0][2] == b"VP8X":
        return b
    if len(cs) != 1:
        raise ValueError("simple-format WebP must hold exactly one image chunk")
    s, e, c = cs[0]
    data = b[s + 8:e]
    if c == b"VP8L":
        v = int.from_bytes(data[1:5], "little")
        w, h, alpha = (v & 0x3FFF) + 1, ((v >> 14) & 0x3FFF) + 1, (v >> 28) & 1
    elif c == b"VP8 ":
        w = struct.unpack("<H", data[6:8])[0] & 0x3FFF
        h = struct.unpack("<H", data[8:10])[0] & 0x3FFF
        alpha = 0
    else:
        raise ValueError("unsupported WebP image chunk %r" % c)
    vp8x = bytes([0x10 if alpha else 0]) + b"\x00\x00\x00" + \
        (w - 1).to_bytes(3, "little") + (h - 1).to_bytes(3, "little")
    return _build(b"VP8X" + struct.pack("<I", 10) + vp8x + b[s:e])


def embed(b: bytes, manifest_json: bytes) -> bytes:
    """Replace any existing manifest; append the chunk as the last chunk (REQ-0225).
    Note: a simple-format input is extended first, so compute artifact.id over
    strip(embed(...)), i.e. over extend(input)."""
    b = strip(extend(b))
    pad = b"\x00" if len(manifest_json) & 1 else b""
    return _build(b[12:] + FOURCC + struct.pack("<I", len(manifest_json)) + manifest_json + pad)
