"""DSSP Core — Schema conformance tests."""

import pytest

try:
    from jsonschema import validate, ValidationError, Draft202012Validator
    import referencing  # noqa: F401 — presence check only

    HAS_REFERENCING = True
except ImportError:
    from jsonschema import validate, ValidationError, RefResolver

    HAS_REFERENCING = False


def _make_validator(schema: dict, schema_registry):
    """Create a validator with proper $ref resolution."""
    if HAS_REFERENCING:
        return Draft202012Validator(schema, registry=schema_registry)
    else:
        # Legacy fallback using RefResolver
        resolver = RefResolver.from_schema(schema, store=schema_registry)
        return None, resolver  # Will use validate() directly


def _validate(instance, schema, schema_registry):
    """Validate an instance against a schema with $ref resolution."""
    if HAS_REFERENCING:
        validator = Draft202012Validator(schema, registry=schema_registry)
        validator.validate(instance)
    else:
        resolver = RefResolver.from_schema(schema, store=schema_registry)
        validate(instance, schema, resolver=resolver)


@pytest.mark.core
class TestManifestSchema:
    def test_valid_manifest(self, load_schema, sample_manifest, schema_registry):
        schema = load_schema("manifest.schema.json")
        _validate(sample_manifest, schema, schema_registry)

    def test_manifest_requires_dssp_version(
        self, load_schema, sample_manifest, schema_registry
    ):
        schema = load_schema("manifest.schema.json")
        invalid = {k: v for k, v in sample_manifest.items() if k != "dssp_version"}
        with pytest.raises((ValidationError, Exception)):
            _validate(invalid, schema, schema_registry)

    def test_manifest_requires_documents(
        self, load_schema, sample_manifest, schema_registry
    ):
        schema = load_schema("manifest.schema.json")
        invalid = {k: v for k, v in sample_manifest.items() if k != "documents"}
        with pytest.raises((ValidationError, Exception)):
            _validate(invalid, schema, schema_registry)


@pytest.mark.core
class TestContractSchema:
    def test_valid_contract(self, load_schema, sample_contract, schema_registry):
        schema = load_schema("contract.schema.json")
        _validate(sample_contract, schema, schema_registry)

    def test_contract_requires_consumer(
        self, load_schema, sample_contract, schema_registry
    ):
        schema = load_schema("contract.schema.json")
        invalid = {k: v for k, v in sample_contract.items() if k != "consumer"}
        with pytest.raises((ValidationError, Exception)):
            _validate(invalid, schema, schema_registry)


@pytest.mark.core
class TestResultSchema:
    def test_valid_result(self, load_schema, sample_result, schema_registry):
        schema = load_schema("result.schema.json")
        _validate(sample_result, schema, schema_registry)


@pytest.mark.core
class TestAuditEventSchema:
    def test_valid_audit_events(self, load_schema, sample_audit_trail, schema_registry):
        schema = load_schema("audit-event.schema.json")
        events = (
            sample_audit_trail
            if isinstance(sample_audit_trail, list)
            else sample_audit_trail.get("events", [sample_audit_trail])
        )
        for event in events:
            _validate(event, schema, schema_registry)
