# SPDX-License-Identifier: Apache-2.0
"""Building and signing manifests (Producer role, SPEC §4, §8)."""

from __future__ import annotations

import base64
from dataclasses import dataclass, field
from datetime import datetime, timezone

from . import embed as containers
from .canon import b64u, commit_prompt, method_for, new_salt
from .digest import artifact_urn
from .jcs import canonicalize
from .keys import Signer
from .tsa import DEFAULT_TSA_URL, request_timestamp

SPEC = "ailineage/0.1"


def signing_input(manifest: dict) -> bytes:
    """UTF-8 JCS of the manifest without `signature` and annotation members (REQ-0500/0501)."""
    return canonicalize({k: v for k, v in manifest.items()
                         if k != "signature" and not k.startswith("_")})


def now_rfc3339() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass
class Opening:
    """The private half of a salted commitment: keep it where the plaintext is kept
    (REQ-0309). Never put it in the manifest."""

    prompt_hash: str
    canonicalization: str
    text: str
    salt: str  # base64url without padding
    attachments: list[str] | None = None

    def to_dict(self) -> dict:
        d = {"prompt_hash": self.prompt_hash, "canonicalization": self.canonicalization,
             "text": self.text, "salt": self.salt}
        if self.attachments is not None:
            d["attachments"] = self.attachments
        return d


def prompt_commitment(text: str, storage: str = "none", attachments: list[str] | None = None,
                      disclosure_policy: str | None = None, contains_pii: bool = False,
                      escrow_ref: str | None = None, **extra) -> tuple[dict, Opening | None]:
    """Return (manifest `prompt` object, opening). Salted for storage none/escrow (REQ-0052)."""
    salted = storage != "public"
    salt = new_salt() if salted else None
    method = method_for(attachments, salted)
    h = commit_prompt(text, attachments, salt)
    p = {"hash": h, "canonicalization": method, "storage": storage,
         "disclosure_policy": disclosure_policy or ("public" if storage == "public" else "none"),
         "contains_pii": contains_pii}
    if storage == "public":
        p["text"] = text
    if storage == "escrow":
        if not escrow_ref:
            raise ValueError("storage=escrow requires escrow_ref")
        p["escrow_ref"] = escrow_ref
    p.update(extra)
    opening = Opening(h, method, text, b64u(salt), attachments) if salted else None
    return p, opening


@dataclass
class Producer:
    """Signs manifests with one key and timestamps them at one TSA."""

    signer: Signer
    tsa_url: str = DEFAULT_TSA_URL
    actor: dict = field(default_factory=dict)

    def build(self, artifact: bytes, media_type: str, kind: str, model: dict, prompt: dict,
              parents: list | None = None, runtime: dict | None = None,
              flags: list | None = None, created_at: str | None = None,
              actor: dict | None = None, **extra) -> dict:
        """Build an unsigned manifest for `artifact` (already in final encoded form;
        use embed.prepare() for container files)."""
        m = {
            "spec": SPEC,
            "artifact": {"id": artifact_urn(artifact), "media_type": media_type,
                         "created_at": created_at or now_rfc3339(), "size_bytes": len(artifact)},
            "generation": {"kind": kind, "model": model},
            "prompt": prompt,
            "parents": parents or [],
            "actor": actor or self.actor,
            "flags": flags or [],
        }
        if runtime:
            m["generation"]["runtime"] = runtime
        m.update(extra)
        return m

    def sign(self, manifest: dict) -> dict:
        """Sign and timestamp; raises TSAError if no token can be obtained (REQ-0506)."""
        m = dict(manifest)
        m.pop("signature", None)
        sig = self.signer.sign(signing_input(m))
        token = request_timestamp(sig, self.tsa_url)
        m["signature"] = {"alg": self.signer.alg, "kid": self.signer.kid,
                          "sig": b64u(sig), "ts": base64.b64encode(token).decode()}
        return m

    def sign_file_bytes(self, data: bytes, **build_kw) -> tuple[bytes, dict]:
        """Build, sign and embed for PNG/JPEG/WebP. Returns (new file bytes, manifest)."""
        prepared = containers.prepare(data)
        m = self.sign(self.build(prepared, **build_kw))
        return containers.embed(prepared, canonicalize(m)), m
