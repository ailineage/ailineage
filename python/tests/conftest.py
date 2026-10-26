# SPDX-License-Identifier: Apache-2.0
import json
import os
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
CANDIDATES = [os.environ.get("AILINEAGE_SPEC_DIR"), HERE.parents[1] / "spec",
              HERE.parents[2] / "spec"]


def _spec_dir() -> Path:
    for c in CANDIDATES:
        if c and (Path(c) / "fixtures" / "index.json").exists():
            return Path(c)
    pytest.exit("spec repository not found; set AILINEAGE_SPEC_DIR", returncode=2)


SPEC = _spec_dir()


@pytest.fixture(scope="session")
def spec_dir() -> Path:
    return SPEC


@pytest.fixture(scope="session")
def index() -> dict:
    return json.loads((SPEC / "fixtures" / "index.json").read_text())


@pytest.fixture(scope="session")
def test_policy(index):
    from ailineage.tsa import load_roots
    from ailineage.verify import TrustPolicy
    tp = index["trust_policy"]
    return TrustPolicy(name=tp["name"], signing_keys=set(tp["signing_keys"]),
                       tsa_roots=load_roots([SPEC / r for r in tp["tsa_roots"]]))
