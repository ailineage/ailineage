# SPDX-License-Identifier: Apache-2.0
"""Verification algorithm (SPEC §9): PROVENANCED, UNPROVENANCED or PROVENANCE_BROKEN."""

from __future__ import annotations

import base64
import binascii
import json
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from importlib import resources
from pathlib import Path

from . import embed as containers
from .canon import b64u_dec, commit_prompt
from .digest import artifact_urn
from .embed import text
from .jcs import loads
from .keys import resolve_did_key, verify_signature
from .manifest import SPEC, signing_input
from .tsa import load_roots, verify_timestamp

PROVENANCED = "PROVENANCED"
UNPROVENANCED = "UNPROVENANCED"
BROKEN = "PROVENANCE_BROKEN"

SKEW = timedelta(seconds=300)    # REQ-0508
DELAY = timedelta(hours=24)      # REQ-0608


@dataclass
class TrustPolicy:
    name: str = "local"
    signing_keys: set[str] = field(default_factory=set)  # DIDs without fragment
    tsa_roots: list = field(default_factory=list)       # cryptography x509 certificates
    strict_tsa: bool = False                            # REQ-0604
    revoked: dict[str, tuple[datetime | None, bool]] = field(default_factory=dict)
    known_extensions: set[str] = field(default_factory=set)

    @classmethod
    def load(cls, path: str | Path) -> "TrustPolicy":
        """JSON: {name, signing_keys: [did], tsa_roots: [pem path relative to the file]}."""
        p = Path(path)
        d = json.loads(p.read_text())
        return cls(name=d.get("name", p.name), signing_keys=set(d.get("signing_keys", [])),
                   tsa_roots=load_roots([p.parent / r for r in d.get("tsa_roots", [])]),
                   strict_tsa=d.get("strict_tsa", False))


@dataclass
class Result:
    state: str
    reason: str | None = None
    warnings: list[str] = field(default_factory=list)
    detail: str = ""
    policy: str = ""
    manifest: dict | None = None
    gen_time: datetime | None = None

    def __str__(self):
        s = self.state if not self.reason else "%s(%s)" % (self.state, self.reason)
        return s + ("" if not self.warnings else " " + ",".join(self.warnings))

    def to_dict(self) -> dict:
        return {"state": self.state, "reason": self.reason, "warnings": self.warnings,
                "detail": self.detail, "trust_policy": self.policy,
                "gen_time": self.gen_time.isoformat() if self.gen_time else None}


_VALIDATOR = None


def _validator():
    global _VALIDATOR
    if _VALIDATOR is None:
        from jsonschema import Draft202012Validator, FormatChecker
        from referencing import Registry, Resource
        root = resources.files("ailineage") / "schema"
        reg = Registry()
        docs = [root / "lineage-0.1.json"] + [f for f in (root / "defs").iterdir()
                                              if f.name.endswith(".json")]
        main = None
        for f in docs:
            d = json.loads(f.read_text())
            reg = reg.with_resource(d["$id"], Resource.from_contents(d))
            if f.name == "lineage-0.1.json":
                main = d
        _VALIDATOR = Draft202012Validator(main, registry=reg, format_checker=FormatChecker())
    return _VALIDATOR


def schema_errors(m) -> list[str]:
    return [("%s: %s" % ("/".join(map(str, e.absolute_path)), e.message))
            for e in _validator().iter_errors(m)]


def semantic_errors(m: dict) -> list[str]:
    errs = []
    parents = m.get("parents", [])
    if m["artifact"]["id"] in [p.get("id") for p in parents]:
        errs.append("REQ-0072: parent id equals artifact.id")
    pairs = [(p.get("id"), p.get("relation")) for p in parents]
    if len(pairs) != len(set(pairs)):
        errs.append("REQ-0075: duplicate (id, relation) in parents")
    if sum(1 for p in parents if p.get("relation") == "previous_version") > 1:
        errs.append("REQ-0077: more than one previous_version parent")
    return errs


def _broken(reason, detail, policy, m=None, warnings=None):
    return Result(BROKEN, reason, warnings or [], detail, policy, m)


def _parse_time(s: str) -> datetime:
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


def locate(artifact: bytes, path: str | Path | None = None) -> list[bytes]:
    """Verifier step 1: embedded manifests first, then the sidecar file."""
    found = containers.extract(artifact)
    if not found and path is not None:
        sc = text.sidecar_path(path)
        if sc.exists():
            found = [sc.read_bytes()]
    return found


def verify(artifact: bytes | None, policy: TrustPolicy, manifest: bytes | dict | None = None,
           path: str | Path | None = None) -> Result:
    """Run SPEC §9.2 steps 1–11 (chain mode is not implemented yet).

    `artifact` may be None only together with an out-of-band `manifest`, for
    structure-only checks; the result then stops after step 5 or reports
    HASH_MISMATCH.
    """
    pol = policy.name
    # 1. Locate
    try:
        found = [manifest] if manifest is not None else locate(artifact, path)
    except ValueError as e:  # container cannot be parsed while looking for the manifest
        return _broken("SCHEMA_INVALID", str(e), pol)
    if not found:
        return Result(UNPROVENANCED, policy=pol)
    if len(found) > 1:
        return _broken("SCHEMA_INVALID", "more than one embedded manifest", pol)
    raw = found[0]
    # 2. Parse
    try:
        m = raw if isinstance(raw, dict) else loads(raw)
    except (ValueError, UnicodeDecodeError) as e:
        return _broken("SCHEMA_INVALID", "not I-JSON: %s" % e, pol)
    if not isinstance(m, dict):
        return _broken("SCHEMA_INVALID", "manifest is not an object", pol)
    warnings = []
    if any(k.startswith("_") for k in m):
        warnings.append("W_ANNOTATION_PRESENT")
    # 3. Version
    if m.get("spec") != SPEC:
        return _broken("SCHEMA_INVALID", "unsupported spec version %r" % m.get("spec"), pol, m)
    # 4. Schema
    errs = schema_errors(m)
    if errs:
        return _broken("SCHEMA_INVALID", "; ".join(errs[:5]), pol, m, warnings)
    # 5. Semantic rules
    errs = semantic_errors(m)
    if errs:
        return _broken("SCHEMA_INVALID", "; ".join(errs), pol, m, warnings)
    for ns in m.get("extensions", {}):
        if ns not in policy.known_extensions and "W_UNKNOWN_EXTENSION" not in warnings:
            warnings.append("W_UNKNOWN_EXTENSION")
    # 6. Artifact binding
    if artifact is None:
        return _broken("HASH_MISMATCH", "no artifact bytes supplied", pol, m, warnings)
    hb = containers.hashable_bytes(artifact)
    aid = artifact_urn(hb)
    a = m["artifact"]
    if aid != a["id"]:
        return _broken("HASH_MISMATCH", "artifact.id %s != computed %s" % (a["id"], aid),
                       pol, m, warnings)
    if "size_bytes" in a and a["size_bytes"] != len(hb):
        return _broken("HASH_MISMATCH", "size_bytes mismatch", pol, m, warnings)
    if containers.detect(artifact) is None:
        hid = text.header_id(artifact)
        if hid is not None and hid != a["id"]:
            return _broken("HASH_MISMATCH", "header identifier differs (REQ-0222)", pol, m,
                           warnings)
    # 7. Public prompt
    pr = m["prompt"]
    if pr["storage"] == "public" and pr["canonicalization"] == "utf8-nfc-trim-v1":
        if commit_prompt(pr["text"]) != pr["hash"]:
            return _broken("HASH_MISMATCH", "prompt.text does not match prompt.hash (REQ-0302)",
                           pol, m, warnings)
    # 8. Key resolution and trust
    sig = m["signature"]
    try:
        key_alg, pub = resolve_did_key(sig["kid"])
    except ValueError as e:
        return _broken("KEY_UNTRUSTED", str(e), pol, m, warnings)
    did = sig["kid"].split("#")[0]
    if did not in policy.signing_keys:
        return _broken("KEY_UNTRUSTED", "%s is not in trust policy %r" % (did, pol), pol, m,
                       warnings)
    # 9. Signature
    try:
        sig_bytes = b64u_dec(sig["sig"])
    except (binascii.Error, ValueError):
        return _broken("SIG_INVALID", "sig is not base64url", pol, m, warnings)
    if key_alg != sig["alg"] or not verify_signature(sig["alg"], pub, signing_input(m),
                                                     sig_bytes):
        return _broken("SIG_INVALID", "signature does not verify", pol, m, warnings)
    # 10. Timestamp
    try:
        token = base64.b64decode(sig["ts"], validate=True)
    except (binascii.Error, ValueError):
        return _broken("TS_INVALID", "ts is not base64", pol, m, warnings)
    ts = verify_timestamp(token, sig_bytes, policy.tsa_roots)
    if not ts.valid:
        return _broken("TS_INVALID", ts.error, pol, m, warnings)
    created = _parse_time(a["created_at"])
    if created > ts.gen_time + SKEW:
        return _broken("TS_INVALID", "created_at is after genTime + 300 s (REQ-0508)", pol, m,
                       warnings)
    if not ts.trusted:
        if policy.strict_tsa:
            return _broken("TS_INVALID", "TSA not in trust policy (strict)", pol, m, warnings)
        warnings.append("W_TSA_UNTRUSTED")
    if ts.gen_time - created > DELAY:
        warnings.append("W_TS_DELAYED")
    # 11. Revocation
    if did in policy.revoked:
        when, compromised = policy.revoked[did]
        if compromised or (when is not None and when < ts.gen_time):
            return _broken("KEY_REVOKED", "key revoked", pol, m, warnings)
    r = Result(PROVENANCED, None, warnings, "", pol, m)
    r.gen_time = ts.gen_time
    return r
