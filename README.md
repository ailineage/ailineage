# AILineage reference implementation

Reference implementation of the [AILineage specification](../spec/SPEC.md) `ailineage/0.1`: signed, timestamped provenance manifests for AI-generated artifacts.

| Path | What | Status |
| --- | --- | --- |
| [`python/`](python/) | Python library `ailineage` and CLI | 0.1.0.dev0: JCS, salted prompt commitments, Ed25519/ES256, did:key, RFC 3161 client and verifier, PNG/JPEG/WebP embedding, sidecar, Verifier steps 1–11 |
| [`integrations/comfyui/`](integrations/comfyui/) | ComfyUI node `AILineage Save Image (signed)` | first version |
| `go/` | Go library and `ail` CLI | next |

Chain mode (Verifier step 12), `did:web`, Registry and escrow are not implemented yet.

## Tests

Golden tests run every case of the spec's `fixtures/index.json`. The spec repository is expected next to this one (`../spec`), or set `SPEC=`.

```sh
make venv
make test           # needs network for the producer tests (freetsa.org)
make test-offline   # skips tests that request new timestamps
```

## CLI

```sh
ailineage keygen                       # ~/.config/ailineage/key.pem, mode 0600; prints the DID
ailineage sign out.png --model black-forest-labs/flux-schnell --provider bfl.ai \
  --principal did:web:example.com --prompt "a red fox"
ailineage verify out.png --policy trust.json
ailineage inspect out.png
ailineage id out.png                   # artifact.id of the hashable bytes
```

A trust policy is JSON: `{"name": "...", "signing_keys": ["did:key:z6Mk..."], "tsa_roots": ["freetsa-cacert.pem"]}`. Paths are relative to the policy file.

Openings (prompt plaintext and salt) of `storage = none` commitments are written to `~/.local/share/ailineage/openings/<artifact hex>.json` with mode 0600, outside the output directory, so they survive moving or deleting the artifact. Back that directory up: without the salt a commitment can never be opened ([REQ-0311]).

## License

Apache-2.0. The specification itself is CC-BY-4.0.
