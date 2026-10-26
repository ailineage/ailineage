# SPDX-License-Identifier: Apache-2.0
"""Producer round trip with a fresh key and the real TSA (network)."""
import os

import pytest

from ailineage import embed
from ailineage.canon import verify_opening
from ailineage.keys import generate_signer
from ailineage.manifest import Producer, prompt_commitment
from ailineage.tsa import TSAError, load_roots
from ailineage.verify import TrustPolicy, verify
from conftest import SPEC

pytestmark = pytest.mark.skipif(os.environ.get("AILINEAGE_OFFLINE") == "1",
                                reason="needs freetsa.org")


@pytest.mark.parametrize("name,alg", [("image-64.png", "EdDSA"), ("image-64.jpg", "ES256"),
                                      ("image-64.webp", "EdDSA")])
def test_sign_embed_verify(name, alg):
    signer = generate_signer(alg=alg)
    prod = Producer(signer, actor={"principal": "did:web:example.com", "role": "operator",
                                   "pseudonymous": False})
    prompt, opening = prompt_commitment("A fox in the snow", storage="none")
    src = (SPEC / "fixtures" / "data" / name).read_bytes()
    try:
        out, m = prod.sign_file_bytes(src, media_type="image/x", kind="created",
                                      model={"id": "black-forest-labs/flux-schnell",
                                             "provider": "bfl.ai"}, prompt=prompt)
    except TSAError as e:
        pytest.skip(str(e))
    policy = TrustPolicy("t", {signer.did},
                         load_roots([SPEC / "fixtures" / "keys" / "freetsa-cacert.pem"]))
    r = verify(out, policy)
    assert r.state == "PROVENANCED", r.detail
    assert verify_opening(m["prompt"]["hash"], opening.canonicalization, opening.text,
                          opening.salt)
    assert embed.hashable_bytes(out) == embed.prepare(src)
