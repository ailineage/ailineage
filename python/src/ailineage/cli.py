# SPDX-License-Identifier: Apache-2.0
"""Command-line interface: `ailineage keygen|sign|verify|inspect|id`."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from . import embed as containers
from . import openings as store
from .digest import artifact_urn
from .embed import text
from .jcs import canonicalize, loads
from .keys import generate_signer, load_signer
from .manifest import Producer, prompt_commitment
from .tsa import DEFAULT_TSA_URL, TSAError
from .verify import TrustPolicy, verify

DEFAULT_KEY = Path(os.environ.get("AILINEAGE_KEY",
                                  Path.home() / ".config" / "ailineage" / "key.pem"))
MEDIA = {"png": "image/png", "jpeg": "image/jpeg", "webp": "image/webp"}


def cmd_keygen(a) -> int:
    s = generate_signer(a.out, a.alg)
    print(s.did)
    return 0


def cmd_id(a) -> int:
    print(artifact_urn(containers.hashable_bytes(Path(a.file).read_bytes())))
    return 0


def cmd_inspect(a) -> int:
    b = Path(a.file).read_bytes()
    found = containers.extract(b)
    sc = text.sidecar_path(a.file)
    if not found and sc.exists():
        found = [sc.read_bytes()]
    if not found:
        print("no manifest found", file=sys.stderr)
        return 1
    for m in found:
        print(json.dumps(loads(m), ensure_ascii=False, indent=2))
    return 0


def cmd_sign(a) -> int:
    path = Path(a.file)
    data = path.read_bytes()
    signer = load_signer(a.key)
    prod = Producer(signer, a.tsa, actor={"principal": a.principal, "role": a.role,
                                          "pseudonymous": False})
    ptext = Path(a.prompt_file).read_text() if a.prompt_file else a.prompt
    prompt, opening = prompt_commitment(ptext, storage=a.storage)
    model = {"id": a.model, "provider": a.provider}
    if a.model_version:
        model["version_hash"] = a.model_version
    c = containers.detect(data)
    media = a.media_type or MEDIA.get(c)
    if not media:
        print("unknown media type; pass --media-type", file=sys.stderr)
        return 2
    kw = dict(media_type=media, kind=a.kind, model=model, prompt=prompt,
              runtime={"tool": a.tool} if a.tool else None)
    try:
        if c and not a.sidecar:
            out, m = prod.sign_file_bytes(data, **kw)
            path.write_bytes(out)
        else:
            m = prod.sign(prod.build(containers.hashable_bytes(data), **kw))
            text.sidecar_path(path).write_text(json.dumps(m, ensure_ascii=False, indent=2) + "\n")
    except TSAError as e:
        print("not signed: %s (REQ-0506)" % e, file=sys.stderr)
        return 1
    if opening:
        store.save(m["artifact"]["id"], m, {"prompt": opening}, a.openings_dir)
    print(m["artifact"]["id"])
    return 0


def cmd_verify(a) -> int:
    policy = TrustPolicy.load(a.policy) if a.policy else TrustPolicy(name="empty")
    b = Path(a.file).read_bytes()
    mf = Path(a.manifest).read_bytes() if a.manifest else None
    r = verify(b, policy, manifest=mf, path=a.file)
    if a.json:
        print(json.dumps(r.to_dict(), indent=2))
    else:
        print(r, ("— " + r.detail) if r.detail else "")
    return 0 if r.state == "PROVENANCED" else 1


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="ailineage", description=__doc__)
    sub = ap.add_subparsers(dest="cmd", required=True)
    k = sub.add_parser("keygen", help="generate a signing key (mode 0600)")
    k.add_argument("--out", default=DEFAULT_KEY)
    k.add_argument("--alg", choices=["EdDSA", "ES256"], default="EdDSA")
    k.set_defaults(fn=cmd_keygen)
    i = sub.add_parser("id", help="print artifact.id of a file")
    i.add_argument("file")
    i.set_defaults(fn=cmd_id)
    n = sub.add_parser("inspect", help="print the embedded or sidecar manifest")
    n.add_argument("file")
    n.set_defaults(fn=cmd_inspect)
    s = sub.add_parser("sign", help="sign a file (embed for PNG/JPEG/WebP, else sidecar)")
    s.add_argument("file")
    s.add_argument("--key", default=DEFAULT_KEY)
    s.add_argument("--tsa", default=DEFAULT_TSA_URL)
    s.add_argument("--model", required=True)
    s.add_argument("--provider", required=True)
    s.add_argument("--model-version")
    g = s.add_mutually_exclusive_group(required=True)
    g.add_argument("--prompt")
    g.add_argument("--prompt-file")
    s.add_argument("--storage", choices=["none", "public"], default="none")
    s.add_argument("--kind", default="created",
                   choices=["created", "edited", "derived", "assisted"])
    s.add_argument("--media-type")
    s.add_argument("--principal", required=True)
    s.add_argument("--role", default="operator")
    s.add_argument("--tool")
    s.add_argument("--sidecar", action="store_true")
    s.add_argument("--openings-dir", type=Path)
    s.set_defaults(fn=cmd_sign)
    v = sub.add_parser("verify", help="verify a file")
    v.add_argument("file")
    v.add_argument("--manifest")
    v.add_argument("--policy", help="trust policy JSON")
    v.add_argument("--json", action="store_true")
    v.set_defaults(fn=cmd_verify)
    a = ap.parse_args(argv)
    return a.fn(a)


if __name__ == "__main__":
    sys.exit(main())
