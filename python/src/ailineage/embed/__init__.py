# SPDX-License-Identifier: Apache-2.0
"""Container dispatch: find embedded manifests and compute hashable bytes (SPEC §5)."""

from __future__ import annotations

from . import jpeg, png, text, webp

CONTAINERS = {"png": png, "jpeg": jpeg, "webp": webp}


def detect(b: bytes) -> str | None:
    """Sniff the container from magic bytes, never from the file name."""
    if png.is_png(b):
        return "png"
    if jpeg.is_jpeg(b):
        return "jpeg"
    if webp.is_webp(b):
        return "webp"
    return None


def extract(b: bytes) -> list[bytes]:
    c = detect(b)
    return CONTAINERS[c].extract(b) if c else []


def hashable_bytes(b: bytes) -> bytes:
    """Artifact bytes with every embedded manifest (and a text header) removed."""
    c = detect(b)
    if c:
        return CONTAINERS[c].strip(b)
    return text.strip_header(b)


def embed(b: bytes, manifest_json: bytes) -> bytes:
    c = detect(b)
    if not c:
        raise ValueError("no embedding for this format; use a sidecar file")
    return CONTAINERS[c].embed(b, manifest_json)


def prepare(b: bytes) -> bytes:
    """Bytes the Producer hashes before embedding: strips any old manifest and
    converts simple WebP to the extended format (REQ-0201, REQ-0226)."""
    c = detect(b)
    if c == "webp":
        return webp.strip(webp.extend(b))
    return hashable_bytes(b)
