# SPDX-License-Identifier: Apache-2.0
"""Read generation facts from a ComfyUI API-format prompt graph.

The graph maps node id -> {"class_type": str, "inputs": {name: value | [node_id, slot]}}.
No ComfyUI imports here, so this module is unit-testable on its own.
"""

from __future__ import annotations

import copy

SAMPLERS = {"KSampler", "KSamplerAdvanced", "SamplerCustom", "SamplerCustomAdvanced"}
# inputs followed from a sampler towards the positive prompt
COND_INPUTS = ("positive", "guider", "conditioning", "conditioning_to", "cond")
# inputs followed from a sampler towards the model loader
MODEL_INPUTS = ("model", "guider")
TEXT_KEYS = ("text", "t5xxl", "clip_l", "clip_g", "prompt", "value", "string")
LOADERS = {"ckpt_name": "checkpoints", "unet_name": "diffusion_models"}
SEED_KEYS = ("seed", "noise_seed")
PARAM_KEYS = ("steps", "cfg", "sampler_name", "scheduler", "denoise", "guidance",
              "width", "height", "batch_size", "start_at_step", "end_at_step")


def _is_link(v) -> bool:
    return isinstance(v, list) and len(v) == 2 and isinstance(v[0], (str, int))


def samplers(g: dict) -> list[str]:
    return sorted((k for k, n in g.items() if n.get("class_type") in SAMPLERS), key=str)


def _walk(g: dict, start: str, follow: tuple[str, ...], limit: int = 64):
    """Breadth-first over links reachable through the named inputs."""
    seen, queue = set(), [start]
    while queue and len(seen) < limit:
        nid = queue.pop(0)
        if nid in seen or nid not in g:
            continue
        seen.add(nid)
        yield nid, g[nid]
        for name, v in g[nid].get("inputs", {}).items():
            if _is_link(v) and (name in follow or not follow):
                queue.append(str(v[0]))


def _string_value(g: dict, v, depth: int = 0) -> str | None:
    if isinstance(v, str):
        return v
    if _is_link(v) and depth < 8:
        n = g.get(str(v[0]), {})
        for k in TEXT_KEYS:
            if k in n.get("inputs", {}):
                s = _string_value(g, n["inputs"][k], depth + 1)
                if s is not None:
                    return s
    return None


def positive_prompt(g: dict) -> str | None:
    """Text of the first text-encoder node reachable from a sampler's positive input."""
    for sid in samplers(g):
        for nid, n in _walk(g, sid, COND_INPUTS):
            if nid == sid or "negative" in n.get("_meta", {}).get("title", "").lower():
                continue
            for k in TEXT_KEYS:
                if k in n.get("inputs", {}):
                    s = _string_value(g, n["inputs"][k])
                    if s and s.strip():
                        return s
    return None


def model_files(g: dict) -> tuple[list[tuple[str, str]], list[str]]:
    """([(folder, file name)] of base model loaders, [LoRA file names])."""
    bases, loras = [], []
    for sid in samplers(g):
        for _, n in _walk(g, sid, MODEL_INPUTS + ("model",)):
            ins = n.get("inputs", {})
            for key, folder in LOADERS.items():
                if isinstance(ins.get(key), str) and (folder, ins[key]) not in bases:
                    bases.append((folder, ins[key]))
            if isinstance(ins.get("lora_name"), str) and ins["lora_name"] not in loras:
                loras.append(ins["lora_name"])
    return bases, loras


def seed_and_params(g: dict) -> tuple[int | None, dict]:
    """Seed and literal sampler parameters of the first sampler (and its noise/latent nodes)."""
    seed, params = None, {}
    for sid in samplers(g)[:1]:
        for _, n in _walk(g, sid, ("noise", "sampler", "sigmas", "latent_image", "guider")):
            for k, v in n.get("inputs", {}).items():
                if k in SEED_KEYS and isinstance(v, int) and seed is None:
                    seed = v
                elif k in PARAM_KEYS and not _is_link(v) and k not in params:
                    params[k] = v
    return seed, params


def redact(g: dict, texts: list[str]) -> dict:
    """Copy of the graph with prompt-bearing strings replaced by '<prompt>' (REQ-0037)."""
    out = copy.deepcopy(g)
    for n in out.values():
        n.pop("_meta", None)
        for k, v in n.get("inputs", {}).items():
            if isinstance(v, str) and (v in texts or (k in TEXT_KEYS and k not in ("value",)
                                                      and n.get("class_type", "").startswith(
                                                          "CLIPTextEncode"))):
                n["inputs"][k] = "<prompt>"
    return out
