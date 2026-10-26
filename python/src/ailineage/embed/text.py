# SPDX-License-Identifier: Apache-2.0
"""Text and code: header comment and sidecar file (SPEC §5.5)."""

from __future__ import annotations

import re
from pathlib import Path

HEADER_RE = re.compile(rb"ailineage: (urn:sha256:[0-9a-f]{64})")
SIDECAR_SUFFIX = ".lineage.json"


def header_id(b: bytes) -> str | None:
    for line in b.splitlines(keepends=True)[:3]:
        m = HEADER_RE.search(line)
        if m:
            return m.group(1).decode()
    return None


def strip_header(b: bytes) -> bytes:
    """Remove the first header line within the first three lines (REQ-0221)."""
    lines = b.splitlines(keepends=True)
    for i, line in enumerate(lines[:3]):
        if HEADER_RE.search(line):
            return b"".join(lines[:i] + lines[i + 1:])
    return b


def sidecar_path(path: str | Path) -> Path:
    p = Path(path)
    return p.with_name(p.name + SIDECAR_SUFFIX)
