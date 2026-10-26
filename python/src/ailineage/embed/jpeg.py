# SPDX-License-Identifier: Apache-2.0
"""JPEG: JUMBF box labelled `ailineage` in APP11 segments (SPEC §5.3)."""

from __future__ import annotations

import struct

JSON_UUID = bytes.fromhex("6a736f6e00110010800000aa00389b71")
LABEL = b"ailineage"
MAX_PAYLOAD = 0xFFFF - 2 - 8 - 8  # Le, CI+En+Z, repeated LBox+TBox
APP11 = 0xEB
SOS = 0xDA


def is_jpeg(b: bytes) -> bool:
    return b[:3] == b"\xff\xd8\xff"


def segments(b: bytes):
    """Yield (start, end, marker) for marker segments before the first SOS,
    then (start, len(b), SOS) for the scan and everything after it."""
    if not b.startswith(b"\xff\xd8"):
        raise ValueError("not a JPEG")
    i = 2
    while i < len(b):
        if b[i] != 0xFF:
            raise ValueError("bad JPEG marker at %d" % i)
        m = b[i + 1]
        if m == 0xFF:  # fill byte
            i += 1
            continue
        if m == SOS or m == 0xD9:
            yield i, len(b), m
            return
        (n,) = struct.unpack(">H", b[i + 2:i + 4])
        if n < 2 or i + 2 + n > len(b):
            raise ValueError("truncated JPEG segment at %d" % i)
        yield i, i + 2 + n, m
        i += 2 + n


def _jp(b: bytes, s: int, e: int):
    """Return (En, Z, box bytes) of an APP11 'JP' segment."""
    seg = b[s + 4:e]
    if len(seg) < 16 or seg[:2] != b"JP":
        return None
    (en,) = struct.unpack(">H", seg[2:4])
    (z,) = struct.unpack(">I", seg[4:8])
    return en, z, seg[8:]


def _first_is_ours(box: bytes) -> bool:
    return (box[4:8] == b"jumb" and box[12:16] == b"jumd" and box[16:32] == JSON_UUID
            and len(box) > 33 and box[32] & 0x02 and box[33:].split(b"\x00", 1)[0] == LABEL)


def _ours(b: bytes) -> dict[int, list[tuple[int, bytes]]]:
    """En -> [(Z, box part)] for every AILineage JUMBF box."""
    segs = [(s, e, _jp(b, s, e)) for s, e, m in segments(b) if m == APP11]
    ens = {jp[0] for _, _, jp in segs if jp and jp[1] == 1 and _first_is_ours(jp[2])}
    out: dict[int, list] = {}
    for _, _, jp in segs:
        if jp and jp[0] in ens:
            out.setdefault(jp[0], []).append((jp[1], jp[2]))
    return out


def extract(b: bytes) -> list[bytes]:
    res = []
    for parts in _ours(b).values():
        parts.sort()
        if [z for z, _ in parts] != list(range(1, len(parts) + 1)):
            raise ValueError("JUMBF packet sequence is not contiguous")
        head = parts[0][1][:8]
        payload = b"".join(p[8:] for _, p in parts)
        (lbox,) = struct.unpack(">I", head[:4])
        if lbox != 8 + len(payload):
            raise ValueError("JUMBF superbox length mismatch")
        (dlen,) = struct.unpack(">I", payload[:4])
        jbox = payload[dlen:]
        (jlen,) = struct.unpack(">I", jbox[:4])
        if jbox[4:8] != b"json" or jlen != len(jbox):
            raise ValueError("AILineage JUMBF box must hold exactly one json box (REQ-0215)")
        res.append(jbox[8:])
    return res


def strip(b: bytes) -> bytes:
    ens = set(_ours(b))
    out = bytearray(b[:2])
    for s, e, m in segments(b):
        if m == APP11:
            jp = _jp(b, s, e)
            if jp and jp[0] in ens:
                continue
        out += b[s:e]
    return bytes(out)


def _used_en(b: bytes) -> set[int]:
    return {jp[0] for s, e, m in segments(b) if m == APP11 and (jp := _jp(b, s, e))}


def embed(b: bytes, manifest_json: bytes) -> bytes:
    """Replace any existing manifest; insert APP11 segment(s) after the header's APPn
    segments (REQ-0216)."""
    b = strip(b)
    used = _used_en(b)
    en = next(x for x in [0x4149] + list(range(1, 0x10000)) if x not in used)
    label = LABEL + b"\x00"
    jumd = struct.pack(">I", 8 + 16 + 1 + len(label)) + b"jumd" + JSON_UUID + b"\x03" + label
    jbox = struct.pack(">I", 8 + len(manifest_json)) + b"json" + manifest_json
    payload = jumd + jbox
    head = struct.pack(">I", 8 + len(payload)) + b"jumb"
    segs = bytearray()
    for z, off in enumerate(range(0, len(payload), MAX_PAYLOAD), start=1):
        body = b"JP" + struct.pack(">HI", en, z) + head + payload[off:off + MAX_PAYLOAD]
        segs += b"\xff\xeb" + struct.pack(">H", 2 + len(body)) + body
    at = 2
    for s, e, m in segments(b):
        if 0xE0 <= m <= 0xEF:
            at = e
        else:
            break
    return b[:at] + bytes(segs) + b[at:]
