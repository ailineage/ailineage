# AILineage monorepo. The spec repository is expected at ../spec (or set SPEC).
SPEC   ?= $(abspath ../spec)
PYTHON ?= .venv/bin/python

.PHONY: venv test test-offline schema-check sync-schema

venv:
	python3 -m venv .venv
	.venv/bin/pip install -q -e "python[test]" pillow numpy

test: schema-check
	AILINEAGE_SPEC_DIR=$(SPEC) $(PYTHON) -m pytest -q python/tests integrations/comfyui/tests

test-offline: schema-check
	AILINEAGE_OFFLINE=1 AILINEAGE_SPEC_DIR=$(SPEC) $(PYTHON) -m pytest -q python/tests integrations/comfyui/tests

# The Python package ships a copy of the JSON Schema; it must equal the spec's.
schema-check:
	diff -r $(SPEC)/schema/defs python/src/ailineage/schema/defs
	diff $(SPEC)/schema/lineage-0.1.json python/src/ailineage/schema/lineage-0.1.json

sync-schema:
	cp $(SPEC)/schema/lineage-0.1.json python/src/ailineage/schema/
	cp $(SPEC)/schema/defs/*.json python/src/ailineage/schema/defs/
