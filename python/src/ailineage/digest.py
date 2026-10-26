# SPDX-License-Identifier: Apache-2.0
"""Digest format `<alg>:<hex>` and artifact identifiers `urn:<alg>:<hex>` (SPEC §5.6)."""

from __future__ import annotations

import hashlib
import re

# Digest algorithm registry (SPEC §15): name -> hex length
REGISTRY = {"sha256": 64}

_DIGEST = re.compile(r"^([a-z0-9-]+):([0-9a-f]+)$")
_URN = re.compile(r"^urn:([a-z0-9-]+):([0-9a-f]+)$")


def sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def digest(b: bytes) -> str:
    return "sha256:" + sha256_hex(b)


def artifact_urn(b: bytes) -> str:
    return "urn:sha256:" + sha256_hex(b)


def _check(alg: str, hx: str) -> bool:
    return REGISTRY.get(alg) == len(hx)


def is_digest(s: str) -> bool:
    m = _DIGEST.match(s)
    return bool(m) and _check(*m.groups())


def is_urn(s: str) -> bool:
    m = _URN.match(s)
    return bool(m) and _check(*m.groups())
