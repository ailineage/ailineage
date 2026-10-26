# ailineage (Python)

Python reference implementation of the AILineage specification `ailineage/0.1`. See the [monorepo README](../README.md) for the CLI, tests and status.

```python
from ailineage import Producer, TrustPolicy, verify, generate_signer
from ailineage.manifest import prompt_commitment

prod = Producer(generate_signer(), actor={"principal": "did:web:example.com",
                                          "role": "operator", "pseudonymous": False})
prompt, opening = prompt_commitment("a red fox", storage="none")   # keep `opening` private
png, manifest = prod.sign_file_bytes(open("in.png", "rb").read(), media_type="image/png",
                                     kind="created", prompt=prompt,
                                     model={"id": "black-forest-labs/flux-schnell",
                                            "provider": "bfl.ai"})
```
