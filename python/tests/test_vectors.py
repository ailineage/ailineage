# SPDX-License-Identifier: Apache-2.0
"""CANONICALIZATION.md test vectors."""
import json

import pytest

from ailineage.canon import canon_text, commit_prompt, params_hash, prompt_bytes, verify_opening
from ailineage.jcs import DuplicateKeyError, canonicalize, loads
from conftest import SPEC

V = json.loads((SPEC / "fixtures" / "vectors" / "canonicalization.json").read_text())


@pytest.mark.parametrize("v", V["prompt"], ids=lambda v: v["name"])
def test_prompt(v):
    assert canon_text(v["input"]) == v["canonical"]
    assert commit_prompt(v["input"]) == v["hash"]


@pytest.mark.parametrize("v", V["salted"], ids=lambda v: v["name"])
def test_salted(v):
    salt = bytes.fromhex(v["salt_hex"])
    assert (salt + prompt_bytes(v["input"])).hex() == v["hashed_bytes_hex"]
    assert commit_prompt(v["input"], salt=salt) == v["hash"]
    assert verify_opening(v["hash"], "utf8-nfc-trim-salted-v1", v["input"], v["salt_b64url"])
    assert not verify_opening(v["hash"], "utf8-nfc-trim-salted-v1", v["input"] + "!",
                              v["salt_b64url"])


def test_jcs():
    assert canonicalize(V["jcs"]["input"]).decode() == V["jcs"]["canonical"]


def test_multimodal():
    i = V["multimodal"]["input"]
    assert prompt_bytes(i["text"], i["attachments"]).decode() == V["multimodal"]["canonical"]
    assert commit_prompt(i["text"], i["attachments"]) == V["multimodal"]["hash"]
    s = V["multimodal_salted"]
    assert commit_prompt(s["input"]["text"], s["input"]["attachments"],
                         bytes.fromhex(s["salt_hex"])) == s["hash"]


def test_params():
    p = V["params"]
    assert canonicalize({k: v for k, v in p["input"]["params"].items()
                         if k not in p["input"]["volatile"]}).decode() == p["canonical"]
    assert params_hash(p["input"]["params"], p["input"]["volatile"]) == p["hash"]


def test_ijson_rejects_duplicates():
    with pytest.raises(DuplicateKeyError):
        loads('{"a":1,"a":2}')
    with pytest.raises(ValueError):
        loads('{"a":NaN}')


def test_openings(spec_dir):
    """Every TEST ONLY opening in the spec opens its fixture's commitment."""
    ops = json.loads((spec_dir / "fixtures" / "data" / "openings.json").read_text())
    n = 0
    for fx, items in ops.items():
        if fx.startswith("_"):
            continue
        m = json.loads((spec_dir / "fixtures" / "valid" / fx).read_text())
        for o in items:
            target = m["prompt"]["hash"] if o["field"] == "prompt.hash" \
                else m["prompt"]["system_prompt_hash"]
            assert verify_opening(target, o["canonicalization"], o["text"], o["salt"]), fx
            n += 1
    assert n >= 10
