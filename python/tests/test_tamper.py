# SPDX-License-Identifier: Apache-2.0
"""Each Verifier step reports its own reason code."""
import base64
import copy
import json

import pytest

from ailineage import embed
from ailineage.canon import b64u
from ailineage.jcs import canonicalize
from ailineage.verify import TrustPolicy, verify
from conftest import SPEC

FX = SPEC / "fixtures"


def load(name):
    return json.loads((FX / "valid" / name).read_text())


def data(name):
    return (FX / "data" / name).read_bytes()


def test_unprovenanced(test_policy):
    assert verify(data("image-64.png"), test_policy).state == "UNPROVENANCED"


def test_hash_mismatch(test_policy):
    m = load("01-image-created-comfyui.json")
    r = verify(data("image-64-inpaint.png"), test_policy, manifest=m)
    assert r.reason == "HASH_MISMATCH"


def test_public_prompt_mismatch(test_policy):
    m = load("10-prompt-public.json")
    m["prompt"]["text"] += " (edited)"
    assert verify(data("haiku.txt"), test_policy, manifest=m).reason == "HASH_MISMATCH"


def test_untrusted_key(test_policy):
    p = copy.copy(test_policy)
    p.signing_keys = set()
    m = load("11-minimal.json")
    assert verify(data("minimal.txt"), p, manifest=m).reason == "KEY_UNTRUSTED"


def test_sig_invalid(test_policy):
    m = load("11-minimal.json")
    m["flags"] = ["training-opt-out"]
    assert verify(data("minimal.txt"), test_policy, manifest=m).reason == "SIG_INVALID"


def test_ts_invalid(test_policy):
    m = load("11-minimal.json")
    other = load("12-pseudonymous-actor.json")
    m["signature"]["ts"] = other["signature"]["ts"]  # token over another signature
    assert verify(data("minimal.txt"), test_policy, manifest=m).reason == "TS_INVALID"


def test_tsa_untrusted_warning(test_policy):
    p = copy.copy(test_policy)
    p.tsa_roots = []
    r = verify(data("minimal.txt"), p, manifest=load("11-minimal.json"))
    assert r.state == "PROVENANCED" and "W_TSA_UNTRUSTED" in r.warnings
    p.strict_tsa = True
    assert verify(data("minimal.txt"), p, manifest=load("11-minimal.json")).reason == "TS_INVALID"


def test_revoked(test_policy):
    p = copy.copy(test_policy)
    m = load("11-minimal.json")
    p.revoked = {m["signature"]["kid"].split("#")[0]: (None, True)}
    assert verify(data("minimal.txt"), p, manifest=m).reason == "KEY_REVOKED"


def test_two_embedded_manifests(test_policy):
    b = (SPEC / "examples" / "png-itxt" / "image-64.ailineage.png").read_bytes()
    from ailineage.embed import png
    chunk = [b[s:e] for s, e, t, d in png.chunks(b) if t == b"iTXt"][0]
    i = b.index(chunk)
    doubled = b[:i] + chunk + b[i:]
    assert verify(doubled, test_policy).reason == "SCHEMA_INVALID"


@pytest.mark.parametrize("name", ["image-64.png", "image-64.jpg", "image-64.webp"])
def test_embed_roundtrip(name):
    src = data(name)
    prepared = embed.prepare(src)
    out = embed.embed(prepared, b'{"x":1}')
    assert embed.hashable_bytes(out) == prepared
    assert embed.extract(out) == [b'{"x":1}']
    again = embed.embed(out, b'{"y":2}')  # replaces, never duplicates
    assert embed.extract(again) == [b'{"y":2}']
    assert embed.hashable_bytes(again) == prepared


def test_jpeg_multisegment():
    src = data("image-64.jpg")
    big = b"{" + b" " * 140000 + b"}"
    out = embed.embed(src, big)
    assert embed.hashable_bytes(out) == src and embed.extract(out) == [big]
