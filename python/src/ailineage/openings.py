# SPDX-License-Identifier: Apache-2.0
"""Local store for openings (plaintext + salt) of storage=none commitments (REQ-0309).

Openings are kept outside the artifact's directory, keyed by artifact id, so they
survive moving or backing up the artifact. Files are written with mode 0600.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

DEFAULT_DIR = Path(os.environ.get("AILINEAGE_OPENINGS_DIR",
                                  Path.home() / ".local" / "share" / "ailineage" / "openings"))


def save(artifact_id: str, manifest: dict, openings: dict, directory: Path | None = None) -> Path:
    """Write {artifact_id, prompt_hash, openings: {name: opening}} to <dir>/<hex>.json."""
    d = Path(directory or DEFAULT_DIR)
    d.mkdir(parents=True, exist_ok=True, mode=0o700)
    p = d / (artifact_id.rsplit(":", 1)[-1] + ".json")
    doc = {"artifact_id": artifact_id, "created_at": manifest["artifact"]["created_at"],
           "openings": {k: v.to_dict() for k, v in openings.items()}}
    tmp = p.with_suffix(".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(doc, f, ensure_ascii=False, indent=2)
        f.write("\n")
    os.replace(tmp, p)
    return p


def load(artifact_id: str, directory: Path | None = None) -> dict | None:
    p = Path(directory or DEFAULT_DIR) / (artifact_id.rsplit(":", 1)[-1] + ".json")
    return json.loads(p.read_text()) if p.exists() else None
