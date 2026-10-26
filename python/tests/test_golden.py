# SPDX-License-Identifier: Apache-2.0
"""Golden tests: every case of spec/fixtures/index.json."""
import json

import pytest

from ailineage.verify import verify
from conftest import SPEC

CASES = json.loads((SPEC / "fixtures" / "index.json").read_text())["cases"]


@pytest.mark.parametrize("case", CASES, ids=lambda c: "%s@%s" % (
    c["manifest"].rsplit("/", 1)[-1], c["locate"]))
def test_case(case, test_policy):
    art = (SPEC / case["artifact"]).read_bytes() if case["artifact"] else None
    manifest = (SPEC / case["manifest"]).read_bytes()
    if case["locate"] == "out-of-band":
        r = verify(art, test_policy, manifest=manifest)
    else:
        r = verify(art, test_policy, path=SPEC / case["artifact"])
        assert r.manifest == json.loads(manifest)
    assert r.state == case["expect"], r.detail
    assert r.reason == case.get("reason"), r.detail
    if r.state == "PROVENANCED":
        assert "W_TSA_UNTRUSTED" not in r.warnings
