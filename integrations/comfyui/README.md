# ComfyUI-AILineage

ComfyUI node **AILineage Save Image (signed)**, category `image/ailineage`. Use it in place of `SaveImage`. For every image in the batch it:

1. encodes the image as PNG, JPEG or WebP;
2. finds the positive prompt, seed, sampler parameters, base model and LoRAs in the API graph (or takes `prompt_text` if connected);
3. commits the prompt with a fresh 32-byte salt (`storage = none`) or puts it in the manifest (`public`);
4. hashes the model weights (cached in `~/.cache/ailineage/weights.json` by path, size and mtime);
5. signs the manifest with `~/.config/ailineage/key.pem` (generated on first use, mode 0600) and gets an RFC 3161 timestamp from freetsa.org;
6. embeds the manifest (PNG `iTXt`, JPEG APP11/JUMBF, WebP `AILN` chunk) and saves the file;
7. writes the opening (prompt + salt) to `~/.local/share/ailineage/openings/`.

The output `artifact_ids` lists the `urn:sha256:` identifiers, one per line.

If no timestamp can be obtained after three attempts, the image is saved **unsigned** and an error is logged ([REQ-0506] forbids publishing a manifest without a timestamp).

By default ComfyUI's own `prompt`/`workflow` PNG text chunks are **not** written, because they contain the prompt in plain text. Turn on `embed_workflow` if you need drag-and-drop workflows back.

## Configuration

| Variable | Default |
| --- | --- |
| `AILINEAGE_KEY` | `~/.config/ailineage/key.pem` |
| `AILINEAGE_PRINCIPAL` | `did:web:ol1n.com` |
| `AILINEAGE_TSA_URL` | `https://freetsa.org/tsr` |
| `AILINEAGE_OPENINGS_DIR` | `~/.local/share/ailineage/openings` |
| `AILINEAGE_CONFIG_DIR` | `~/.config/ailineage` (also `models.json`) |

`models.json` maps weight file names (or regular expressions) to `generation.model`:

```json
{ "my-finetune-v3.safetensors": { "id": "ol1n/tsumiki-v3", "provider": "ol1n.com" } }
```

Unknown files get `local/<file stem>` with provider `local.invalid`.

## Install

```sh
<ComfyUI>/.venv/bin/pip install /path/to/ailineage/python
ln -s /path/to/ailineage/integrations/comfyui/ComfyUI-AILineage <ComfyUI>/custom_nodes/
# restart ComfyUI
```
