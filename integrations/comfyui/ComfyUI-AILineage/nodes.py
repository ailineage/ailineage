# SPDX-License-Identifier: Apache-2.0
"""ComfyUI node `AILineage Save Image`: save, sign, timestamp and embed a manifest."""

from __future__ import annotations

import io
import json
import logging
import os
import time

import numpy as np
from PIL import Image

import folder_paths

from ailineage import embed
from ailineage.canon import params_hash
from ailineage.digest import artifact_urn, digest
from ailineage.jcs import canonicalize
from ailineage.keys import generate_signer, load_signer
from ailineage.manifest import Producer, prompt_commitment
from ailineage import openings as store
from ailineage.tsa import DEFAULT_TSA_URL, TSAError

from . import graph, models

log = logging.getLogger("ailineage")

KEY_PATH = os.environ.get("AILINEAGE_KEY", models.CONFIG_DIR / "key.pem")
PRINCIPAL = os.environ.get("AILINEAGE_PRINCIPAL", "did:web:ol1n.com")
TSA_URL = os.environ.get("AILINEAGE_TSA_URL", DEFAULT_TSA_URL)
EXT = "org.ailineage.comfyui"

_signer = None


def signer():
    global _signer
    if _signer is None:
        if not os.path.exists(KEY_PATH):
            _signer = generate_signer(KEY_PATH)
            log.warning("AILineage: generated new signing key %s (%s)", KEY_PATH, _signer.did)
        else:
            _signer = load_signer(KEY_PATH)
    return _signer


def comfy_version() -> str:
    try:
        from comfyui_version import __version__
        return "ComfyUI " + __version__
    except ImportError:
        return "ComfyUI"


def _encode(img: Image.Image, fmt: str, quality: int) -> bytes:
    buf = io.BytesIO()
    if fmt == "png":
        img.save(buf, "PNG", compress_level=4)
    elif fmt == "jpeg":
        img.convert("RGB").save(buf, "JPEG", quality=quality)
    else:
        img.save(buf, "WEBP", lossless=quality >= 100, quality=min(quality, 100), method=4)
    return buf.getvalue()


def _sign_with_retry(prod: Producer, data: bytes, kw: dict, tries: int = 3):
    for i in range(tries):
        try:
            return prod.sign_file_bytes(data, **kw)
        except TSAError as e:
            log.warning("AILineage: TSA attempt %d/%d failed: %s", i + 1, tries, e)
            time.sleep(2 * (i + 1))
    return None


class AILineageSaveImage:
    """Drop-in replacement for SaveImage that embeds a signed AILineage manifest."""

    def __init__(self):
        self.output_dir = folder_paths.get_output_directory()

    @classmethod
    def INPUT_TYPES(cls):
        return {
            "required": {
                "images": ("IMAGE",),
                "filename_prefix": ("STRING", {"default": "ailineage"}),
                "format": (["png", "jpeg", "webp"], {"default": "png"}),
                "quality": ("INT", {"default": 95, "min": 1, "max": 100,
                                    "tooltip": "JPEG/WebP quality; 100 = lossless WebP"}),
                "prompt_storage": (["none", "public"], {
                    "default": "none",
                    "tooltip": "none: only a salted hash goes in the manifest; the prompt and "
                               "salt are kept locally. public: the prompt text is in the manifest."}),
            },
            "optional": {
                "prompt_text": ("STRING", {"default": "", "tooltip":
                                           "The user's prompt; empty = take the positive "
                                           "prompt found in the graph"}),
                "model_id": ("STRING", {"default": "", "tooltip": "<provider>/<model>; "
                                        "empty = derive from the loader node"}),
                "model_provider": ("STRING", {"default": ""}),
                "hash_weights": ("BOOLEAN", {"default": True,
                                             "tooltip": "sha256 of the weights (cached)"}),
                "embed_workflow": ("BOOLEAN", {"default": False, "tooltip":
                                               "Also write ComfyUI's prompt/workflow PNG text "
                                               "chunks. They contain the prompt in plain text."}),
            },
            "hidden": {"prompt": "PROMPT", "extra_pnginfo": "EXTRA_PNGINFO"},
        }

    RETURN_TYPES = ("STRING",)
    RETURN_NAMES = ("artifact_ids",)
    FUNCTION = "save"
    OUTPUT_NODE = True
    CATEGORY = "image/ailineage"
    DESCRIPTION = "Saves images with an embedded, signed and timestamped AILineage manifest."

    def save(self, images, filename_prefix, format, quality, prompt_storage, prompt_text=None,
             model_id="", model_provider="", hash_weights=True, embed_workflow=False,
             prompt=None, extra_pnginfo=None):
        g = prompt or {}
        text = prompt_text if prompt_text else graph.positive_prompt(g)
        model, loras = self._model(g, model_id, model_provider, hash_weights)
        seed, params = graph.seed_and_params(g)
        runtime = {"tool": comfy_version()}
        if g:
            runtime["workflow_hash"] = digest(canonicalize(graph.redact(g, [text] if text else [])))
        if seed is not None:
            runtime["seed"] = seed
        if params:
            runtime["params_hash"] = params_hash(params)
        prod = Producer(signer(), TSA_URL, actor={"principal": PRINCIPAL, "role": "operator",
                                                  "pseudonymous": False})
        ext = {EXT: {"loras": loras}} if loras else None
        kind = graph.generation_kind(g)
        parents = self._parents(g)
        if kind != "created" and not any(p["relation"] == "input" for p in parents):
            kind = "created"  # input image not readable: do not claim an edit without a parent
        h, w = images[0].shape[0], images[0].shape[1]
        full_dir, fname, counter, subfolder, _ = folder_paths.get_save_image_path(
            filename_prefix, self.output_dir, w, h)
        results, ids = [], []
        suffix = {"png": "png", "jpeg": "jpg", "webp": "webp"}[format]
        for batch_number, image in enumerate(images):
            arr = np.clip(255.0 * image.cpu().numpy(), 0, 255).astype(np.uint8)
            img = Image.fromarray(arr)
            if format == "png" and embed_workflow:
                img.info = {}
                data = self._png_with_workflow(img, g, extra_pnginfo)
            else:
                data = _encode(img, format, quality)
            name = "%s_%05d_.%s" % (fname.replace("%batch_num%", str(batch_number)), counter,
                                    suffix)
            out = data
            if text is None:
                log.error("AILineage: no prompt found in the graph; saving %s unsigned", name)
            else:
                pr, opening = prompt_commitment(text, storage=prompt_storage)
                kw = dict(media_type="image/" + format, kind=kind, model=model, prompt=pr,
                          runtime=runtime, parents=parents)
                if ext:
                    kw["extensions"] = ext
                signed = _sign_with_retry(prod, data, kw)
                if signed is None:
                    log.error("AILineage: no timestamp; saving %s unsigned (REQ-0506)", name)
                else:
                    out, m = signed
                    ids.append(m["artifact"]["id"])
                    if opening:
                        store.save(m["artifact"]["id"], m, {"prompt": opening})
            with open(os.path.join(full_dir, name), "wb") as f:
                f.write(out)
            results.append({"filename": name, "subfolder": subfolder, "type": "output"})
            counter += 1
        return {"ui": {"images": results}, "result": ("\n".join(ids),)}

    @staticmethod
    def _parents(g) -> list:
        """Content ids of the loaded input/reference images (REQ-0070, REQ-0071)."""
        out = []
        for name, rel in graph.input_images(g):
            try:
                path = folder_paths.get_annotated_filepath(name)
                with open(path, "rb") as f:
                    pid = artifact_urn(embed.hashable_bytes(f.read()))
            except (OSError, ValueError) as e:
                log.warning("AILineage: input image %s not hashed: %s", name, e)
                continue
            if all((p["id"], p["relation"]) != (pid, rel) for p in out):
                out.append({"id": pid, "relation": rel})
        return out

    @staticmethod
    def _model(g, model_id, model_provider, hash_weights):
        bases, loras = graph.model_files(g)
        m = models.describe(bases[0][1]) if bases else {"id": "local/unknown",
                                                        "provider": models.FALLBACK_PROVIDER}
        if model_id:
            m["id"] = model_id
        if model_provider:
            m["provider"] = model_provider
        if hash_weights and bases:
            try:
                digests = []
                for folder, name in bases:
                    p = folder_paths.get_full_path(folder, name)
                    if p:
                        digests.append((os.path.basename(p), models.weights_digest(p)))
                if len(digests) == 1:
                    m["version_hash"] = digests[0][1]
                elif digests:  # REQ-0032: JCS array ordered by file name
                    m["version_hash"] = digest(canonicalize([d for _, d in sorted(digests)]))
            except OSError as e:
                log.warning("AILineage: weights not hashed: %s", e)
        return m, loras

    @staticmethod
    def _png_with_workflow(img, g, extra_pnginfo) -> bytes:
        from PIL.PngImagePlugin import PngInfo
        meta = PngInfo()
        if g:
            meta.add_text("prompt", json.dumps(g))
        for k, v in (extra_pnginfo or {}).items():
            meta.add_text(k, json.dumps(v))
        buf = io.BytesIO()
        img.save(buf, "PNG", pnginfo=meta, compress_level=4)
        return buf.getvalue()


NODE_CLASS_MAPPINGS = {"AILineageSaveImage": AILineageSaveImage}
NODE_DISPLAY_NAME_MAPPINGS = {"AILineageSaveImage": "AILineage Save Image (signed)"}
