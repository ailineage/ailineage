# SPDX-License-Identifier: Apache-2.0
"""JSON Canonicalization Scheme (RFC 8785) and strict I-JSON parsing."""

from __future__ import annotations

import json
import math


class DuplicateKeyError(ValueError):
    pass


def _es_number(x) -> str:
    """Serialize a number the way ECMAScript Number.prototype.toString does."""
    if isinstance(x, bool):
        raise TypeError("bool is not a number")
    if isinstance(x, int):
        if abs(x) > 2**53 - 1:
            raise ValueError("integer outside IEEE-754 safe range: %d" % x)
        return str(x)
    if not math.isfinite(x):
        raise ValueError("NaN/Infinity are not allowed in JCS")
    if x == 0:
        return "0"
    sign = "-" if x < 0 else ""
    r = repr(abs(x))  # shortest round-trip representation
    mant, exp = (r.split("e")[0], int(r.split("e")[1])) if "e" in r else (r, 0)
    ip, fp = mant.split(".") if "." in mant else (mant, "")
    lead_zeros = len(ip + fp) - len((ip + fp).lstrip("0"))
    n = len(ip) - lead_zeros + exp  # decimal point position relative to `digits`
    digits = (ip + fp).lstrip("0").rstrip("0") or "0"
    k = len(digits)
    if k <= n <= 21:
        out = digits + "0" * (n - k)
    elif 0 < n <= 21:
        out = digits[:n] + "." + digits[n:]
    elif -6 < n <= 0:
        out = "0." + "0" * (-n) + digits
    else:
        e = n - 1
        out = digits[0] + ("." + digits[1:] if k > 1 else "") + "e" + ("+" if e >= 0 else "-") + str(abs(e))
    return sign + out


def _str(s: str) -> str:
    return json.dumps(s, ensure_ascii=False)


def _ser(value) -> str:
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, (int, float)):
        return _es_number(value)
    if isinstance(value, str):
        return _str(value)
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(_ser(v) for v in value) + "]"
    if isinstance(value, dict):
        keys = sorted(value, key=lambda k: k.encode("utf-16-be"))
        return "{" + ",".join(_str(k) + ":" + _ser(value[k]) for k in keys) + "}"
    raise TypeError("unsupported type %r" % type(value))


def canonicalize(value) -> bytes:
    """Return the UTF-8 bytes of the RFC 8785 serialization of `value`."""
    return _ser(value).encode("utf-8")


def _no_dupes(pairs):
    d = {}
    for k, v in pairs:
        if k in d:
            raise DuplicateKeyError("duplicate member name %r" % k)
        d[k] = v
    return d


def _reject_constant(c):
    raise ValueError("non-finite number %s is not I-JSON" % c)


def loads(data: bytes | str):
    """Parse I-JSON (RFC 7493): UTF-8, no duplicate member names, finite numbers."""
    if isinstance(data, bytes):
        data = data.decode("utf-8")  # raises on invalid UTF-8
    return json.loads(data, object_pairs_hook=_no_dupes, parse_constant=_reject_constant)
