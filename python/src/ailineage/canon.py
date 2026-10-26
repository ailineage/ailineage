# SPDX-License-Identifier: Apache-2.0
"""Prompt canonicalization and commitments (CANONICALIZATION.md §3–§6)."""

from __future__ import annotations

import base64
import hmac
import os
import unicodedata

from .digest import digest
from .jcs import canonicalize

# Unicode White_Space=yes code points, minus U+000A LINE FEED (line separator)
WS = ("\u0009\u000b\u000c\u000d \u0085  "
      + "".join(chr(c) for c in range(0x2000, 0x200B))
      + "    　")

SALTED = {"utf8-nfc-trim-v1": "utf8-nfc-trim-salted-v1",
          "multimodal-v1": "multimodal-salted-v1"}
UNSALTED = {v: k for k, v in SALTED.items()}
METHODS = set(SALTED) | set(UNSALTED)
SALT_LEN = 32


def canon_text(text: str) -> str:
    t = unicodedata.normalize("NFC", text)
    t = t.replace("\r\n", "\n").replace("\r", "\n")
    t = "\n".join(line.rstrip(WS) for line in t.split("\n"))
    return t.strip(WS + "\n")


def prompt_bytes(text: str, attachments: list[str] | None = None) -> bytes:
    """Canonical bytes C: utf8-nfc-trim (attachments None) or multimodal."""
    if attachments is None:
        return canon_text(text).encode("utf-8")
    return canonicalize({"text": canon_text(text), "attachments": list(attachments)})


def new_salt() -> bytes:
    return os.urandom(SALT_LEN)


def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def b64u_dec(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def commit_prompt(text: str, attachments: list[str] | None = None,
                  salt: bytes | None = None) -> str:
    """Return prompt.hash. With `salt` (32 bytes) the salted method, else unsalted."""
    c = prompt_bytes(text, attachments)
    if salt is None:
        return digest(c)
    if len(salt) != SALT_LEN:
        raise ValueError("salt must be exactly 32 bytes")
    return digest(salt + c)


def method_for(attachments: list[str] | None, salted: bool) -> str:
    base = "utf8-nfc-trim-v1" if attachments is None else "multimodal-v1"
    return SALTED[base] if salted else base


def verify_opening(prompt_hash: str, method: str, text: str, salt: bytes | str | None,
                   attachments: list[str] | None = None) -> bool:
    """Check an opening (plaintext, salt) against a commitment (REQ-0310)."""
    if method not in METHODS:
        return False
    multimodal = method.startswith("multimodal")
    if multimodal != (attachments is not None):
        return False
    if method in UNSALTED:
        if salt is None:
            return False
        s = b64u_dec(salt) if isinstance(salt, str) else salt
        if len(s) != SALT_LEN:
            return False
        got = commit_prompt(text, attachments, s)
    else:
        got = commit_prompt(text, attachments)
    return hmac.compare_digest(got, prompt_hash)


def params_hash(params: dict, volatile: list[str] | None = None) -> str:
    drop = set(volatile or [])
    return digest(canonicalize({k: v for k, v in params.items() if k not in drop}))
