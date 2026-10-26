# SPDX-License-Identifier: Apache-2.0
"""AILineage reference implementation for Python (spec ailineage/0.1)."""

from .canon import (commit_prompt, new_salt, params_hash, prompt_bytes, verify_opening)
from .digest import sha256_hex, digest, artifact_urn
from .jcs import canonicalize
from .keys import Signer, load_signer, generate_signer
from .manifest import Producer, signing_input
from .verify import TrustPolicy, Result, verify

SPEC_VERSION = "ailineage/0.1"
__version__ = "0.1.0.dev0"

__all__ = [
    "SPEC_VERSION", "canonicalize", "commit_prompt", "new_salt", "params_hash", "prompt_bytes",
    "verify_opening", "sha256_hex", "digest", "artifact_urn", "Signer", "load_signer",
    "generate_signer", "Producer", "signing_input", "TrustPolicy", "Result", "verify",
]
