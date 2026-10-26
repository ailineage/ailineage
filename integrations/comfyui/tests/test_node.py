# SPDX-License-Identifier: Apache-2.0
"""Node tests with a stub `folder_paths` (no ComfyUI or torch needed)."""
import importlib
import importlib.util
import json
import os
import sys
import types
from pathlib import Path

import numpy as np
import pytest

HERE = Path(__file__).resolve().parent
SPEC = next(p for p in [Path(os.environ.get("AILINEAGE_SPEC_DIR", "/nonexistent")),
                        HERE.parents[2] / "spec", HERE.parents[3] / "spec"]
            if (p / "fixtures" / "index.json").exists())

PKG = HERE.parent / "ComfyUI-AILineage"


def _load_pkg():
    """Load the node directory the way ComfyUI does (by file location)."""
    spec = importlib.util.spec_from_file_location(
        "ailineage_comfy", PKG / "__init__.py", submodule_search_locations=[str(PKG)])
    mod = importlib.util.module_from_spec(spec)
    sys.modules["ailineage_comfy"] = mod
    spec.loader.exec_module(mod)
    return mod


# FLUX schnell graph as exported by ComfyUI "Save (API)", SamplerCustomAdvanced style
FLUX = {
    "6": {"class_type": "CLIPTextEncode", "inputs": {"text": "a red fox, watercolor", "clip": ["11", 0]},
          "_meta": {"title": "CLIP Text Encode (Positive Prompt)"}},
    "8": {"class_type": "VAEDecode", "inputs": {"samples": ["13", 0], "vae": ["10", 0]}},
    "10": {"class_type": "VAELoader", "inputs": {"vae_name": "ae.safetensors"}},
    "11": {"class_type": "DualCLIPLoader", "inputs": {"clip_name1": "t5xxl_fp8.safetensors",
                                                     "clip_name2": "clip_l.safetensors", "type": "flux"}},
    "12": {"class_type": "UNETLoader", "inputs": {"unet_name": "flux1-schnell.safetensors",
                                                 "weight_dtype": "default"}},
    "13": {"class_type": "SamplerCustomAdvanced", "inputs": {
        "noise": ["25", 0], "guider": ["22", 0], "sampler": ["16", 0], "sigmas": ["17", 0],
        "latent_image": ["27", 0]}},
    "16": {"class_type": "KSamplerSelect", "inputs": {"sampler_name": "euler"}},
    "17": {"class_type": "BasicScheduler", "inputs": {"scheduler": "simple", "steps": 4,
                                                     "denoise": 1.0, "model": ["30", 0]}},
    "22": {"class_type": "BasicGuider", "inputs": {"model": ["30", 0], "conditioning": ["6", 0]}},
    "25": {"class_type": "RandomNoise", "inputs": {"noise_seed": 424242}},
    "27": {"class_type": "EmptySD3LatentImage", "inputs": {"width": 64, "height": 64, "batch_size": 1}},
    "30": {"class_type": "LoraLoaderModelOnly", "inputs": {"model": ["12", 0],
                                                          "lora_name": "tsumiki-style.safetensors",
                                                          "strength_model": 0.8}},
    "9": {"class_type": "SaveImage", "inputs": {"images": ["8", 0], "filename_prefix": "x"}},
}

KSAMPLER = {
    "3": {"class_type": "KSampler", "inputs": {"seed": 7, "steps": 20, "cfg": 7.0, "sampler_name": "euler",
                                               "scheduler": "normal", "denoise": 1.0, "model": ["4", 0],
                                               "positive": ["6", 0], "negative": ["7", 0],
                                               "latent_image": ["5", 0]}},
    "4": {"class_type": "CheckpointLoaderSimple", "inputs": {"ckpt_name": "sd_xl_base_1.0.safetensors"}},
    "5": {"class_type": "EmptyLatentImage", "inputs": {"width": 64, "height": 64, "batch_size": 1}},
    "6": {"class_type": "CLIPTextEncode", "inputs": {"text": ["20", 0], "clip": ["4", 1]}},
    "7": {"class_type": "CLIPTextEncode", "inputs": {"text": "blurry", "clip": ["4", 1]}},
    "20": {"class_type": "PrimitiveStringMultiline", "inputs": {"value": "a castle on a hill"}},
}


@pytest.fixture()
def node(tmp_path, monkeypatch):
    fp = types.ModuleType("folder_paths")
    weights = tmp_path / "models"
    weights.mkdir()
    (weights / "flux1-schnell.safetensors").write_bytes(b"fake weights")
    fp.get_output_directory = lambda: str(tmp_path / "out")
    fp.get_full_path = lambda folder, name: str(weights / name) if (weights / name).exists() else None

    def save_path(prefix, out, w, h):
        os.makedirs(out, exist_ok=True)
        return out, prefix, 1, "", prefix
    fp.get_save_image_path = save_path
    monkeypatch.setitem(sys.modules, "folder_paths", fp)
    monkeypatch.setenv("AILINEAGE_KEY", str(tmp_path / "cfg" / "key.pem"))
    monkeypatch.setenv("AILINEAGE_OPENINGS_DIR", str(tmp_path / "openings"))
    monkeypatch.setenv("AILINEAGE_CACHE_DIR", str(tmp_path / "cache"))
    monkeypatch.setenv("AILINEAGE_CONFIG_DIR", str(tmp_path / "cfg"))
    for m in [m for m in sys.modules if m.startswith("ailineage_comfy")]:
        del sys.modules[m]
    import ailineage.openings
    importlib.reload(ailineage.openings)
    pkg = _load_pkg()
    nodes = sys.modules["ailineage_comfy.nodes"]
    yield nodes, tmp_path



def _graph():
    spec = importlib.util.spec_from_file_location("ailineage_comfy_graph", PKG / "graph.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_graph_facts():
    g = _graph()
    assert g.positive_prompt(FLUX) == "a red fox, watercolor"
    assert g.positive_prompt(KSAMPLER) == "a castle on a hill"
    assert g.model_files(FLUX) == ([("diffusion_models", "flux1-schnell.safetensors")],
                                   ["tsumiki-style.safetensors"])
    seed, params = g.seed_and_params(FLUX)
    assert seed == 424242 and params == {"sampler_name": "euler", "scheduler": "simple", "steps": 4,
                                         "denoise": 1.0, "width": 64, "height": 64, "batch_size": 1}
    seed, params = g.seed_and_params(KSAMPLER)
    assert seed == 7 and params["cfg"] == 7.0
    red = json.dumps(g.redact(KSAMPLER, ["a castle on a hill"]))
    assert "castle" not in red and "blurry" not in red


class FakeTensor:
    def __init__(self, a):
        self.a = a
        self.shape = a.shape

    def cpu(self):
        return self

    def numpy(self):
        return self.a


@pytest.mark.skipif(os.environ.get("AILINEAGE_OFFLINE") == "1", reason="needs freetsa.org")
@pytest.mark.parametrize("fmt", ["png", "jpeg", "webp"])
def test_save_sign_verify(node, fmt):
    nodes, tmp = node
    from ailineage import embed, openings
    from ailineage.canon import verify_opening
    from ailineage.tsa import load_roots
    from ailineage.verify import TrustPolicy, verify
    rng = np.random.default_rng(1)
    imgs = [FakeTensor(rng.random((64, 64, 3), dtype=np.float32)) for _ in range(2)]
    n = nodes.AILineageSaveImage()
    res = n.save(imgs, "t", fmt, 90, "none", prompt=FLUX)
    ids = res["result"][0].split("\n")
    assert len(ids) == 2 and len(set(ids)) == 2
    policy = TrustPolicy("t", {nodes.signer().did},
                         load_roots([SPEC / "fixtures" / "keys" / "freetsa-cacert.pem"]))
    for item, aid in zip(res["ui"]["images"], ids):
        b = (tmp / "out" / item["filename"]).read_bytes()
        assert embed.detect(b) == fmt
        r = verify(b, policy)
        assert r.state == "PROVENANCED", r.detail
        m = r.manifest
        assert m["generation"]["model"]["id"] == "black-forest-labs/flux-schnell"
        assert m["generation"]["model"]["version_hash"].startswith("sha256:")
        assert m["generation"]["runtime"]["seed"] == 424242
        assert m["extensions"]["org.ailineage.comfyui"]["loras"] == ["tsumiki-style.safetensors"]
        assert "fox" not in json.dumps(m)
        o = openings.load(aid)["openings"]["prompt"]
        assert o["text"] == "a red fox, watercolor"
        assert verify_opening(m["prompt"]["hash"], o["canonicalization"], o["text"], o["salt"])
    assert oct(os.stat(tmp / "cfg" / "key.pem").st_mode & 0o777) == "0o600"
