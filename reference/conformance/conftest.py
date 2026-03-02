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
    """Build a registry of all DSP schemas for $ref resolution."""
    if HAS_REFERENCING:
        resources = []
        for schema_file in SCHEMA_DIR.glob("*.schema.json"):
            with open(schema_file) as f:
                schema = json.load(f)
            resources.append(
                (schema_file.name, Resource.from_contents(schema, default_specification=DRAFT202012))
            )
        return Registry().with_resources(resources)
    else:
        # Fallback: build a store dict for legacy RefResolver
        store = {}
        for schema_file in SCHEMA_DIR.glob("*.schema.json"):
            with open(schema_file) as f:
                store[schema_file.name] = json.load(f)
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
    return os.environ.get("DSP_GATEWAY_URL", "http://localhost:8080")
