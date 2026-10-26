# SPDX-License-Identifier: Apache-2.0
"""Map weight file names to `generation.model` and hash weights with a cache (REQ-0031/0032)."""

from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path

CONFIG_DIR = Path(os.environ.get("AILINEAGE_CONFIG_DIR", Path.home() / ".config" / "ailineage"))
CACHE = Path(os.environ.get("AILINEAGE_CACHE_DIR", Path.home() / ".cache" / "ailineage")) \
    / "weights.json"

# Built-in guesses by file name; override or extend in ~/.config/ailineage/models.json:
# {"<file name or regex>": {"id": "<provider>/<model>", "provider": "<domain>", "card_ref": "https://…"}}
BUILTIN = [
    (r"flux1?[-_.]?schnell", {"id": "black-forest-labs/flux-schnell", "provider": "bfl.ai",
                             "card_ref": "https://huggingface.co/black-forest-labs/FLUX.1-schnell"}),
    (r"flux1?[-_.]?kontext", {"id": "black-forest-labs/flux-kontext-dev", "provider": "bfl.ai",
                             "card_ref": "https://huggingface.co/black-forest-labs/FLUX.1-Kontext-dev"}),
    (r"flux1?[-_.]?fill", {"id": "black-forest-labs/flux-fill-dev", "provider": "bfl.ai",
                          "card_ref": "https://huggingface.co/black-forest-labs/FLUX.1-Fill-dev"}),
    (r"flux1?[-_.]?dev", {"id": "black-forest-labs/flux-dev", "provider": "bfl.ai",
                         "card_ref": "https://huggingface.co/black-forest-labs/FLUX.1-dev"}),
    (r"sd_?xl", {"id": "stabilityai/stable-diffusion-xl-base-1.0", "provider": "stability.ai"}),
    (r"qwen[-_]?image", {"id": "qwen/qwen-image", "provider": "qwen.ai"}),
    (r"wan2\.?2", {"id": "wan-ai/wan2.2", "provider": "wan.video"}),
]
FALLBACK_PROVIDER = os.environ.get("AILINEAGE_FALLBACK_PROVIDER", "local.invalid")


def _user_map() -> dict:
    p = CONFIG_DIR / "models.json"
    return json.loads(p.read_text()) if p.exists() else {}


def describe(file_name: str) -> dict:
    base = os.path.basename(file_name)
    user = _user_map()
    if base in user:
        return dict(user[base])
    for pat, m in list(user.items()) + BUILTIN:
        if re.search(pat, base, re.IGNORECASE):
            return dict(m)
    stem = re.sub(r"\.(safetensors|ckpt|pt|pth|gguf|bin)$", "", base, flags=re.IGNORECASE)
    slug = re.sub(r"[^A-Za-z0-9._:-]+", "-", stem).strip("-.") or "model"
    return {"id": "local/" + slug, "provider": FALLBACK_PROVIDER}


def weights_digest(path: str) -> str:
    """sha256 over the file, cached by (path, size, mtime) because files are large."""
    st = os.stat(path)
    key = "%s|%d|%d" % (os.path.realpath(path), st.st_size, st.st_mtime_ns)
    cache = json.loads(CACHE.read_text()) if CACHE.exists() else {}
    if key in cache:
        return cache[key]
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(16 << 20), b""):
            h.update(block)
    d = "sha256:" + h.hexdigest()
    cache[key] = d
    CACHE.parent.mkdir(parents=True, exist_ok=True)
    tmp = CACHE.with_suffix(".tmp")
    tmp.write_text(json.dumps(cache, indent=1))
    os.replace(tmp, CACHE)
    return d
