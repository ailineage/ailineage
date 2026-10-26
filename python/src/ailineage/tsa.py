# SPDX-License-Identifier: Apache-2.0
"""RFC 3161 timestamps over the signature bytes (SPEC §8.4)."""

from __future__ import annotations

import hashlib
import os
import urllib.request
from dataclasses import dataclass
from datetime import datetime

from asn1crypto import cms, tsp
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

DEFAULT_TSA_URL = "https://freetsa.org/tsr"

_HASHES = {"sha1": hashes.SHA1, "sha224": hashes.SHA224, "sha256": hashes.SHA256,
           "sha384": hashes.SHA384, "sha512": hashes.SHA512}


class TSAError(Exception):
    pass


def request_timestamp(sig: bytes, url: str = DEFAULT_TSA_URL, timeout: float = 30) -> bytes:
    """Request a TimeStampToken for SHA-256(sig) and return it as DER (REQ-0505, REQ-0507)."""
    imprint = hashlib.sha256(sig).digest()
    nonce = int.from_bytes(os.urandom(8), "big")
    req = tsp.TimeStampReq({
        "version": "v1",
        "message_imprint": {"hash_algorithm": {"algorithm": "sha256"}, "hashed_message": imprint},
        "nonce": nonce,
        "cert_req": True,
    })
    http = urllib.request.Request(url, data=req.dump(),
                                  headers={"Content-Type": "application/timestamp-query"})
    try:
        with urllib.request.urlopen(http, timeout=timeout) as r:
            body = r.read()
    except OSError as e:
        raise TSAError("TSA %s unreachable: %s" % (url, e)) from e
    resp = tsp.TimeStampResp.load(body)
    status = resp["status"]["status"].native
    if status not in ("granted", "granted_with_mods"):
        raise TSAError("TSA refused the request: %s" % status)
    token = resp["time_stamp_token"]
    tst = token["content"]["encap_content_info"]["content"].parsed
    if tst["nonce"].native != nonce:
        raise TSAError("TSA reply nonce mismatch")
    if tst["message_imprint"]["hashed_message"].native != imprint:
        raise TSAError("TSA reply imprint mismatch")
    return token.dump()


@dataclass
class TimestampResult:
    valid: bool
    trusted: bool = False
    gen_time: datetime | None = None
    error: str = ""


def _find_signer_cert(sid, certs):
    for c in certs:
        if sid.name == "issuer_and_serial_number":
            if c.issuer == sid.chosen["issuer"] and c.serial_number == sid.chosen["serial_number"].native:
                return c
        elif c.key_identifier == sid.chosen.native:
            return c
    return None


def _verify_cms_signature(cert: x509.Certificate, si, data: bytes) -> bool:
    algo = si["signature_algorithm"]
    sig = si["signature"].native
    pub = cert.public_key()
    name = algo.signature_algo
    if name == "rsassa_pss":
        hname = algo["parameters"]["hash_algorithm"]["algorithm"].native
    else:
        try:
            hname = algo.hash_algo
        except ValueError:  # e.g. bare rsaEncryption: hash is the SignerInfo digest
            hname = si["digest_algorithm"]["algorithm"].native
    h = _HASHES.get(hname)
    if h is None:
        return False
    try:
        if name == "ecdsa" and isinstance(pub, ec.EllipticCurvePublicKey):
            pub.verify(sig, data, ec.ECDSA(h()))
        elif name == "rsassa_pkcs1v15" and isinstance(pub, rsa.RSAPublicKey):
            pub.verify(sig, data, padding.PKCS1v15(), h())
        elif name == "rsassa_pss" and isinstance(pub, rsa.RSAPublicKey):
            salt = algo["parameters"]["salt_length"].native
            pub.verify(sig, data, padding.PSS(padding.MGF1(h()), salt), h())
        else:
            return False
    except InvalidSignature:
        return False
    return True


def _issued_by(child: x509.Certificate, parent: x509.Certificate) -> bool:
    try:
        child.verify_directly_issued_by(parent)
        return True
    except (ValueError, TypeError, InvalidSignature):
        return False


def _chains_to(cert: x509.Certificate, pool: list[x509.Certificate],
               roots: list[x509.Certificate], at: datetime) -> bool:
    cur = cert
    for _ in range(8):
        for r in roots:
            if cur == r or _issued_by(cur, r):
                return r.not_valid_before_utc <= at <= r.not_valid_after_utc
        nxt = next((c for c in pool if c.subject == cur.issuer and c != cur and _issued_by(cur, c)),
                   None)
        if nxt is None or not (nxt.not_valid_before_utc <= at <= nxt.not_valid_after_utc):
            return False
        cur = nxt
    return False


def verify_timestamp(token_der: bytes, sig: bytes,
                     roots: list[x509.Certificate]) -> TimestampResult:
    """Verify a TimeStampToken over SHA-256(sig) (Verifier step 10).

    `valid` covers the token signature, imprint and certificate binding; `trusted`
    says whether the TSA certificate chains to one of `roots` (else W_TSA_UNTRUSTED).
    """
    try:
        ci = cms.ContentInfo.load(token_der, strict=True)
        if ci["content_type"].native != "signed_data":
            return TimestampResult(False, error="token is not SignedData")
        sd = ci["content"]
        enc = sd["encap_content_info"]
        if enc["content_type"].native != "tst_info":
            return TimestampResult(False, error="eContentType is not TSTInfo")
        econtent = enc["content"].contents
        tst = enc["content"].parsed
        gen_time = tst["gen_time"].native
        mi = tst["message_imprint"]
        if mi["hash_algorithm"]["algorithm"].native != "sha256":
            return TimestampResult(False, gen_time=gen_time, error="imprint is not SHA-256")
        if mi["hashed_message"].native != hashlib.sha256(sig).digest():
            return TimestampResult(False, gen_time=gen_time, error="imprint mismatch")
        if len(sd["signer_infos"]) != 1:
            return TimestampResult(False, gen_time=gen_time, error="expected one SignerInfo")
        si = sd["signer_infos"][0]
        attrs = {a["type"].native: a["values"][0] for a in si["signed_attrs"]}
        dname = si["digest_algorithm"]["algorithm"].native
        if dname not in _HASHES:
            return TimestampResult(False, gen_time=gen_time, error="unsupported digest " + dname)
        if attrs.get("content_type") is None or attrs["content_type"].native != "tst_info":
            return TimestampResult(False, gen_time=gen_time, error="content-type attribute")
        md = attrs.get("message_digest")
        if md is None or md.native != hashlib.new(dname, econtent).digest():
            return TimestampResult(False, gen_time=gen_time, error="message-digest mismatch")
        a1certs = [c.chosen for c in sd["certificates"] if c.name == "certificate"] \
            if sd["certificates"] else []
        a1 = _find_signer_cert(si["sid"], a1certs)
        if a1 is None:
            return TimestampResult(False, gen_time=gen_time,
                                   error="TSA certificate not in token (certReq)")
        # ESSCertID / ESSCertIDv2 binding (RFC 5816)
        if "signing_certificate_v2" in attrs:
            ess = attrs["signing_certificate_v2"]["certs"][0]
            halg = ess["hash_algorithm"]["algorithm"].native
            if ess["cert_hash"].native != hashlib.new(halg, a1.dump()).digest():
                return TimestampResult(False, gen_time=gen_time, error="ESSCertIDv2 mismatch")
        elif "signing_certificate" in attrs:
            ess = attrs["signing_certificate"]["certs"][0]
            if ess["cert_hash"].native != hashlib.sha1(a1.dump()).digest():
                return TimestampResult(False, gen_time=gen_time, error="ESSCertID mismatch")
        signed = si["signed_attrs"].dump()
        signed = b"\x31" + signed[1:]  # [0] IMPLICIT -> SET OF for the signature input
        cert = x509.load_der_x509_certificate(a1.dump())
        if not _verify_cms_signature(cert, si, signed):
            return TimestampResult(False, gen_time=gen_time, error="TSA signature invalid")
        try:
            eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
            if x509.oid.ExtendedKeyUsageOID.TIME_STAMPING not in eku:
                raise x509.ExtensionNotFound("no timeStamping", None)
        except x509.ExtensionNotFound:
            return TimestampResult(False, gen_time=gen_time, error="TSA cert lacks timeStamping EKU")
        if not (cert.not_valid_before_utc <= gen_time <= cert.not_valid_after_utc):
            return TimestampResult(False, gen_time=gen_time, error="TSA cert not valid at genTime")
        pool = [x509.load_der_x509_certificate(c.dump()) for c in a1certs]
        return TimestampResult(True, _chains_to(cert, pool, roots, gen_time), gen_time)
    except (ValueError, TypeError, KeyError, IndexError) as e:
        return TimestampResult(False, error="malformed token: %s" % e)


def load_roots(paths) -> list[x509.Certificate]:
    out = []
    for p in paths:
        with open(p, "rb") as f:
            out += x509.load_pem_x509_certificates(f.read())
    return out
