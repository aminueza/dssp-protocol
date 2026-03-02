"""Shared fixtures for DSP conformance tests."""

import json
import os
from pathlib import Path

import pytest

try:
    from referencing import Registry, Resource
    from referencing.jsonschema import DRAFT202012

    HAS_REFERENCING = True
except ImportError:
    HAS_REFERENCING = False

SPEC_DIR = Path(__file__).parent.parent.parent
SCHEMA_DIR = SPEC_DIR / "schemas"
EXAMPLE_DIR = SPEC_DIR / "examples" / "bank-statement-extraction"


@pytest.fixture
def schema_dir():
    return SCHEMA_DIR


@pytest.fixture
def load_schema():
    def _load(name: str) -> dict:
        path = SCHEMA_DIR / name
        with open(path) as f:
            return json.load(f)

    return _load


@pytest.fixture
def schema_registry():
    """Build a registry of all DSSP schemas for $ref resolution.

    Schemas are registered under both their ``$id`` URI (for absolute refs)
    and their filename (for relative refs like ``common.schema.json``).
    """
    if HAS_REFERENCING:
        from urllib.parse import urljoin

        resources = []
        all_schemas = {}
        for schema_file in SCHEMA_DIR.glob("*.schema.json"):
            with open(schema_file) as f:
                schema = json.load(f)
            resource = Resource.from_contents(schema, default_specification=DRAFT202012)
            all_schemas[schema_file.name] = (schema, resource)
            resources.append((schema_file.name, resource))
            schema_id = schema.get("$id")
            if schema_id:
                resources.append((schema_id, resource))

        # Register each schema under relative URIs that other schemas resolve.
        # When schema A ($id "https://x/manifest/v0.1") does
        # "$ref": "common.schema.json#/...", the resolver looks up
        # "https://x/manifest/common.schema.json". We pre-register these.
        base_ids = [s.get("$id") for s, _ in all_schemas.values() if s.get("$id")]
        for filename, (schema, resource) in all_schemas.items():
            for base_id in base_ids:
                resolved_uri = urljoin(base_id, filename)
                resources.append((resolved_uri, resource))

        return Registry().with_resources(resources)
    else:
        # Fallback for environments without the referencing library
        store = {}
        for schema_file in SCHEMA_DIR.glob("*.schema.json"):
            with open(schema_file) as f:
                schema = json.load(f)
            store[schema_file.name] = schema
            if "$id" in schema:
                store[schema["$id"]] = schema
        return store


@pytest.fixture
def load_example():
    def _load(name: str) -> dict | list:
        path = EXAMPLE_DIR / name
        with open(path) as f:
            return json.load(f)

    return _load


@pytest.fixture
def sample_manifest(load_example):
    return load_example("manifest.json")


@pytest.fixture
def sample_contract(load_example):
    return load_example("contract.json")


@pytest.fixture
def sample_result(load_example):
    return load_example("result.json")


@pytest.fixture
def sample_audit_trail(load_example):
    return load_example("audit-trail.json")


@pytest.fixture
def gateway_url():
    return os.environ.get("DSSP_GATEWAY_URL", "http://localhost:8080")
