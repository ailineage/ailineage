# SPDX-License-Identifier: Apache-2.0
"""Signing keys, did:key identifiers and signature suites (SPEC §8.2, §8.3)."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.primitives.asymmetric.utils import (decode_dss_signature,
                                                            encode_dss_signature)

B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
MC_ED25519 = b"\xed\x01"  # multicodec ed25519-pub (0xed), varint
MC_P256 = b"\x80\x24"     # multicodec p256-pub (0x1200), varint


def b58encode(b: bytes) -> str:
    n = int.from_bytes(b, "big")
    s = ""
    while n:
        n, r = divmod(n, 58)
        s = B58[r] + s
    return "1" * (len(b) - len(b.lstrip(b"\x00"))) + s


def b58decode(s: str) -> bytes:
    n = 0
    for ch in s:
        n = n * 58 + B58.index(ch)
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    return b"\x00" * (len(s) - len(s.lstrip("1"))) + raw


def did_key_for(public_key) -> str:
    """Return the did:key DID (without fragment) for an Ed25519 or P-256 public key."""
    if isinstance(public_key, ed25519.Ed25519PublicKey):
        mc = MC_ED25519 + public_key.public_bytes(serialization.Encoding.Raw,
                                                  serialization.PublicFormat.Raw)
    elif isinstance(public_key, ec.EllipticCurvePublicKey) and \
            isinstance(public_key.curve, ec.SECP256R1):
        mc = MC_P256 + public_key.public_bytes(serialization.Encoding.X962,
                                               serialization.PublicFormat.CompressedPoint)
    else:
        raise ValueError("unsupported key type")
    return "did:key:z" + b58encode(mc)


def resolve_did_key(kid: str):
    """Resolve a did:key DID or DID URL to (alg, public key). Raises ValueError."""
    did, _, frag = kid.partition("#")
    if not did.startswith("did:key:z"):
        raise ValueError("not a did:key: %s" % kid)
    fp = did[len("did:key:"):]
    if frag and frag != fp:
        raise ValueError("did:key fragment does not match the key")
    mc = b58decode(fp[1:])
    if mc[:2] == MC_ED25519 and len(mc) == 34:
        return "EdDSA", ed25519.Ed25519PublicKey.from_public_bytes(mc[2:])
    if mc[:2] == MC_P256 and len(mc) == 35:
        return "ES256", ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), mc[2:])
    raise ValueError("unsupported did:key multicodec")


def verify_signature(alg: str, public_key, msg: bytes, sig: bytes) -> bool:
    if len(sig) != 64:  # REQ-0503
        return False
    try:
        if alg == "EdDSA" and isinstance(public_key, ed25519.Ed25519PublicKey):
            public_key.verify(sig, msg)
            return True
        if alg == "ES256" and isinstance(public_key, ec.EllipticCurvePublicKey):
            der = encode_dss_signature(int.from_bytes(sig[:32], "big"),
                                       int.from_bytes(sig[32:], "big"))
            public_key.verify(der, msg, ec.ECDSA(hashes.SHA256()))
            return True
    except InvalidSignature:
        return False
    return False


@dataclass
class Signer:
    """A private key with its algorithm and did:key `kid`."""

    private_key: object
    alg: str

    @property
    def did(self) -> str:
        return did_key_for(self.private_key.public_key())

    @property
    def kid(self) -> str:
        fp = self.did[len("did:key:"):]
        return "%s#%s" % (self.did, fp)

    def sign(self, msg: bytes) -> bytes:
        if self.alg == "EdDSA":
            return self.private_key.sign(msg)
        r, s = decode_dss_signature(self.private_key.sign(msg, ec.ECDSA(hashes.SHA256())))
        return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def _signer_for(key) -> Signer:
    if isinstance(key, ed25519.Ed25519PrivateKey):
        return Signer(key, "EdDSA")
    if isinstance(key, ec.EllipticCurvePrivateKey) and isinstance(key.curve, ec.SECP256R1):
        return Signer(key, "ES256")
    raise ValueError("unsupported private key type (need Ed25519 or P-256)")


def load_signer(path: str | os.PathLike) -> Signer:
    """Load a PEM (PKCS#8) private key."""
    return _signer_for(serialization.load_pem_private_key(Path(path).read_bytes(), None))


def generate_signer(path: str | os.PathLike | None = None, alg: str = "EdDSA") -> Signer:
    """Generate a key; if `path` is given, write it as PEM with mode 0600 (never overwrites)."""
    key = ed25519.Ed25519PrivateKey.generate() if alg == "EdDSA" else \
        ec.generate_private_key(ec.SECP256R1())
    if path is not None:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                serialization.NoEncryption())
        fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(pem)
    return _signer_for(key)
