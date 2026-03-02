#!/usr/bin/env python3
"""
DSSP Reference Validator — v0.1

Validates DSP messages (manifests, contracts, results, audit events) against
the official JSON schemas. Also performs semantic checks that JSON Schema
alone cannot enforce (PII safety, audit chain integrity, contract compliance).

Usage:
    python validate.py manifest.json
    python validate.py contract.json
    python validate.py result.json --contract contract.json
    python validate.py audit-trail.json --check-chain
    python validate.py --all examples/bank-statement-extraction/

License: Apache 2.0
"""

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

try:
    from jsonschema import Draft202012Validator
    from referencing import Registry, Resource
    from referencing.jsonschema import DRAFT202012
except ImportError:
    print(
        "Error: jsonschema and referencing packages required.\n"
        "Install with: pip install 'jsonschema>=4.20.0' 'referencing>=0.31.0'"
    )
    sys.exit(1)


SCHEMA_DIR = Path(__file__).parent.parent.parent / "schemas"

SCHEMA_MAP = {
    "https://dssp.dev/schema/manifest/v0.1": "manifest.schema.json",
    "https://dssp.dev/schema/contract/v0.1": "contract.schema.json",
    "https://dssp.dev/schema/result/v0.1": "result.schema.json",
    "https://dssp.dev/schema/audit/v0.1": "audit-event.schema.json",
    "https://dssp.dev/schema/storage-binding/v0.1": "storage-binding.schema.json",
    "https://dssp.dev/schema/common/v0.1": "common.schema.json",
}

PII_PATTERNS = {
    "us_ssn": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    "email": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"),
    "phone_us": re.compile(r"\b\(\d{3}\)\s?\d{3}-\d{4}\b"),
    "phone_intl": re.compile(r"\b\+\d{1,3}[-.\s]?\d{4,14}\b"),
    "credit_card": re.compile(r"\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b"),
    "iban": re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}([A-Z0-9]?){0,16}\b"),
}


def _build_registry() -> Registry:
    """Build a referencing.Registry that resolves all DSSP schemas locally.

    Each schema is registered under:
      1. Its canonical $id (e.g. https://dssp.dev/schema/common/v0.1)
      2. Its filename (e.g. common.schema.json) for relative $ref resolution
      3. Directory-relative URIs that jsonschema may construct when resolving
         a relative $ref against a parent schema's $id
         (e.g. https://dssp.dev/schema/audit/common.schema.json)
    """
    resources: list[tuple[str, Resource]] = []

    # Load every schema file once
    loaded: dict[str, dict] = {}
    for schema_id, filename in SCHEMA_MAP.items():
        path = SCHEMA_DIR / filename
        if path.exists():
            with open(path) as f:
                contents = json.load(f)
            loaded[filename] = contents

            resource = Resource.from_contents(
                contents, default_specification=DRAFT202012
            )
            # Register under canonical $id
            resources.append((schema_id, resource))
            # Register under bare filename (for relative $ref)
            resources.append((filename, resource))

    # Register cross-directory relative URIs.
    # When schema A ($id = https://dssp.dev/schema/audit/v0.1) has
    # $ref: "common.schema.json#/...", jsonschema resolves it as
    # https://dssp.dev/schema/audit/common.schema.json.
    # We need to map those constructed URIs to the actual schema.
    for schema_id in SCHEMA_MAP:
        # e.g. "https://dssp.dev/schema/audit/v0.1" -> "https://dssp.dev/schema/audit/"
        base = schema_id.rsplit("/", 1)[0] + "/"
        for filename, contents in loaded.items():
            constructed_uri = base + filename
            resource = Resource.from_contents(
                contents, default_specification=DRAFT202012
            )
            resources.append((constructed_uri, resource))

    return Registry().with_resources(resources)


# Module-level registry (built once, reused across validations)
_REGISTRY: Registry | None = None


def _get_registry() -> Registry:
    global _REGISTRY
    if _REGISTRY is None:
        _REGISTRY = _build_registry()
    return _REGISTRY


def load_schema(schema_id: str) -> dict:
    """Load a DSP schema by its $id."""
    filename = SCHEMA_MAP.get(schema_id)
    if not filename:
        raise ValueError(f"Unknown schema: {schema_id}")
    path = SCHEMA_DIR / filename
    with open(path) as f:
        return json.load(f)


def detect_schema(data: dict) -> str | None:
    """Detect which DSP schema a message uses."""
    return data.get("$schema")


class ValidationResult:
    """Collects validation errors and warnings."""

    def __init__(self, filename: str):
        self.filename = filename
        self.errors: list[str] = []
        self.warnings: list[str] = []

    def error(self, msg: str) -> None:
        self.errors.append(msg)

    def warn(self, msg: str) -> None:
        self.warnings.append(msg)

    @property
    def passed(self) -> bool:
        return len(self.errors) == 0

    def summary(self) -> str:
        lines = [f"\n{'=' * 60}", f"  {self.filename}"]
        if self.passed:
            lines.append(f"  PASSED ({len(self.warnings)} warnings)")
        else:
            lines.append(
                f"  FAILED ({len(self.errors)} errors, {len(self.warnings)} warnings)"
            )
        lines.append(f"{'=' * 60}")
        for e in self.errors:
            lines.append(f"  ERROR: {e}")
        for w in self.warnings:
            lines.append(f"  WARN:  {w}")
        return "\n".join(lines)


def validate_schema(data: dict, result: ValidationResult) -> bool:
    """Validate a message against its JSON schema."""
    schema_id = detect_schema(data)
    if not schema_id:
        result.error("No $schema field found. Cannot determine message type.")
        return False

    try:
        schema = load_schema(schema_id)
    except (ValueError, FileNotFoundError) as e:
        result.error(f"Cannot load schema: {e}")
        return False

    registry = _get_registry()
    validator = Draft202012Validator(schema, registry=registry)

    errors = sorted(validator.iter_errors(data), key=lambda e: list(e.path))
    for error in errors:
        path = ".".join(str(p) for p in error.path) or "(root)"
        result.error(f"Schema: {path}: {error.message}")

    return len(errors) == 0


def scan_for_pii(obj: Any, path: str, result: ValidationResult) -> None:
    """Recursively scan a value for PII patterns."""
    if isinstance(obj, str) and len(obj) > 5:
        for pii_name, pattern in PII_PATTERNS.items():
            if pattern.search(obj):
                result.error(
                    f"PII detected [{pii_name}] at {path}: "
                    f"value contains pattern that looks like {pii_name}"
                )
    elif isinstance(obj, dict):
        for k, v in obj.items():
            scan_for_pii(v, f"{path}.{k}", result)
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            scan_for_pii(v, f"{path}[{i}]", result)


def validate_manifest_pii(data: dict, result: ValidationResult) -> None:
    """Check that a manifest doesn't contain PII."""
    for doc in data.get("documents", []):
        # document_id should be opaque, not a filename
        doc_id = doc.get("document_id", "")
        if "/" in doc_id or "\\" in doc_id or doc_id.endswith(".pdf"):
            result.warn(
                f"Document ID '{doc_id}' looks like a filename. "
                "Use opaque IDs to avoid leaking information."
            )

        # Scan tags and metadata for PII
        for tag in doc.get("tags", []):
            scan_for_pii(tag, f"documents[{doc_id}].tags", result)

        for k, v in doc.get("metadata", {}).items():
            scan_for_pii(v, f"documents[{doc_id}].metadata.{k}", result)


def validate_result_pii(
    data: dict, contract: dict | None, result: ValidationResult
) -> None:
    """Check that a result envelope doesn't leak PII."""
    pii_report = data.get("pii_report", {})

    # raw_content_included should be false
    if pii_report.get("raw_content_included", False):
        if contract:
            allowed = (
                contract.get("restrictions", {})
                .get("result_policy", {})
                .get("raw_content_allowed", False)
            )
            if not allowed:
                result.error(
                    "Result contains raw content but contract does not allow it."
                )
        else:
            result.warn("Result contains raw content. Verify contract allows this.")

    # Scan all extraction fields for PII patterns
    for extraction in data.get("extractions", []):
        fields = extraction.get("fields", {})
        scan_for_pii(
            fields,
            f"extractions[{extraction.get('source_document_id', '?')}].fields",
            result,
        )

        for table in extraction.get("tables", []):
            for i, row in enumerate(table.get("rows", [])):
                scan_for_pii(row, f"tables[{table.get('name', '?')}].rows[{i}]", result)

    # Check compliance status
    compliance = pii_report.get("compliance_status")
    if compliance == "violation_detected":
        result.error("PII report indicates compliance violation was detected.")
    elif compliance == "unknown":
        result.warn("PII compliance status is 'unknown'. Review manually.")


def validate_numeric_precision(
    data: dict, contract: dict, result: ValidationResult
) -> None:
    """Check numeric fields comply with the contract's numeric_precision_policy."""
    policy = (
        contract.get("restrictions", {})
        .get("result_policy", {})
        .get("numeric_precision_policy")
    )
    if not policy:
        return

    max_dp = policy.get("max_decimal_places", 2)
    max_sig = policy.get("max_significant_digits")

    def check_value(val: Any, path: str) -> None:
        if not isinstance(val, (int, float)):
            return
        # Use str() for faithful float representation (avoids IEEE 754 artifacts
        # from f"{val:.20f}" which turns 892341.2 into 892341.19999999995...)
        s = str(val)
        if "." in s:
            decimals = len(s.split(".")[1])
            if decimals > max_dp:
                result.error(
                    f"Numeric precision violation at {path}: "
                    f"{val} has {decimals} decimal places (max {max_dp})"
                )
        # Check significant digits
        if max_sig:
            digits = len(s.replace(".", "").replace("-", "").lstrip("0"))
            if digits > max_sig:
                result.warn(
                    f"Numeric precision warning at {path}: "
                    f"{val} has {digits} significant digits (max {max_sig})"
                )

    for extraction in data.get("extractions", []):
        doc_id = extraction.get("source_document_id", "?")
        for k, v in extraction.get("fields", {}).items():
            check_value(v, f"extractions[{doc_id}].fields.{k}")
        for table in extraction.get("tables", []):
            for ri, row in enumerate(table.get("rows", [])):
                for ci, cell in enumerate(row):
                    check_value(
                        cell, f"tables[{table.get('name', '?')}].rows[{ri}][{ci}]"
                    )


def validate_sub_agent_chain(
    data: dict, contract: dict, result: ValidationResult
) -> None:
    """Check that the sub_agent_chain in the result complies with the contract's sub_agent_policy."""
    chain = data.get("attestation", {}).get("claims", {}).get("sub_agent_chain", [])
    policy = contract.get("consumer", {}).get("sub_agent_policy")

    # If sub_agent_chain_declaration is required but chain is empty with multi-step processing
    must_include = contract.get("attestation_requirements", {}).get("must_include", [])
    if "sub_agent_chain_declaration" in must_include and not chain:
        result.warn(
            "Attestation requires 'sub_agent_chain_declaration' but no sub_agent_chain found. "
            "Acceptable only if processing used a single monolithic agent."
        )

    if not policy or not chain:
        return

    # Check if sub-agents are allowed
    if not policy.get("allowed", True):
        if chain:
            result.error(
                "Sub-agents are not allowed by contract but sub_agent_chain is present."
            )
            return

    # Check max pipeline steps
    max_steps = policy.get("max_pipeline_steps")
    if max_steps and len(chain) > max_steps:
        result.error(
            f"Sub-agent chain has {len(chain)} steps but contract allows max {max_steps}."
        )

    # Check allowed purposes
    allowed_purposes = set(policy.get("allowed_purposes", []))
    if allowed_purposes:
        for step in chain:
            purpose = step.get("purpose", "")
            if purpose and purpose not in allowed_purposes:
                result.error(
                    f"Sub-agent step {step.get('step_index', '?')} has purpose '{purpose}' "
                    f"which is not in allowed_purposes."
                )

    # Check LLM sub-agent restriction
    if not policy.get("llm_sub_agent_allowed", False):
        for step in chain:
            if step.get("agent_type") == "llm_freeform":
                result.error(
                    f"Sub-agent step {step.get('step_index', '?')} is 'llm_freeform' "
                    f"but contract does not allow LLM sub-agents."
                )

    # Check cross-enclave restriction
    if not policy.get("cross_enclave_allowed", False):
        for step in chain:
            if step.get("enclave_shared") is False:
                result.error(
                    f"Sub-agent step {step.get('step_index', '?')} runs in a separate enclave "
                    f"but contract does not allow cross-enclave invocation."
                )

    # Check hash requirements
    if policy.get("require_sub_agent_hashes", True):
        for step in chain:
            if not step.get("agent_hash"):
                result.error(
                    f"Sub-agent step {step.get('step_index', '?')} is missing agent_hash "
                    f"but contract requires sub-agent hashes."
                )


def validate_result_contract_compliance(
    data: dict, contract: dict, result: ValidationResult
) -> None:
    """Check that a result complies with its contract."""
    # Check contract_id matches
    if data.get("contract_id") != contract.get("contract_id"):
        result.error(
            f"Result references contract {data.get('contract_id')} "
            f"but provided contract is {contract.get('contract_id')}"
        )

    # Check network destinations match contract
    claims = data.get("attestation", {}).get("claims", {})
    allowed_dests = set()
    network = contract.get("restrictions", {}).get("network_policy", {})
    for dest in network.get("allowed_destinations", []):
        allowed_dests.add(f"{dest['host']}:{dest['port']}")

    for dest in claims.get("network_destinations", []):
        if dest not in allowed_dests and network.get("egress") == "allow_listed":
            result.error(f"Result contacted unauthorized destination: {dest}")

    # Check PII redaction methods match contract
    contract_rules = (
        contract.get("restrictions", {})
        .get("result_policy", {})
        .get("pii_redaction_rules", {})
    )
    applied_rules = data.get("pii_report", {}).get("redaction_methods_applied", {})
    for field, method in applied_rules.items():
        expected = contract_rules.get(field, "suppress")
        if method != expected:
            result.error(
                f"PII field '{field}' was redacted with '{method}' "
                f"but contract requires '{expected}'"
            )


def validate_audit_chain(events: list[dict], result: ValidationResult) -> None:
    """Verify the Merkle chain integrity of an audit trail."""
    if not events:
        result.warn("Empty audit trail.")
        return

    # Check genesis event
    first = events[0]
    if first.get("event_type") != "ledger.genesis":
        result.warn("First event is not 'ledger.genesis'.")

    if first.get("sequence_number", -1) != 0:
        result.error("Genesis event should have sequence_number 0.")

    # Check chain continuity
    for i in range(1, len(events)):
        prev_event = events[i - 1]
        curr_event = events[i]

        # Check sequence numbers are monotonic
        prev_seq = prev_event.get("sequence_number", -1)
        curr_seq = curr_event.get("sequence_number", -1)
        if curr_seq != prev_seq + 1:
            result.error(
                f"Event {i}: sequence_number gap. "
                f"Expected {prev_seq + 1}, got {curr_seq}"
            )

        # Check previous_event_hash matches previous event's hash
        prev_hash = prev_event.get("event_hash", {}).get("value", "")
        curr_prev_ref = curr_event.get("previous_event_hash", {}).get("value", "")
        if prev_hash and curr_prev_ref and prev_hash != curr_prev_ref:
            result.error(
                f"Event {i}: previous_event_hash mismatch. "
                f"Expected {prev_hash}, got {curr_prev_ref}"
            )

        # Check timestamps are non-decreasing
        prev_ts = prev_event.get("timestamp", "")
        curr_ts = curr_event.get("timestamp", "")
        if prev_ts and curr_ts and curr_ts < prev_ts:
            result.warn(
                f"Event {i}: timestamp {curr_ts} is before "
                f"previous event timestamp {prev_ts}"
            )


def validate_file(
    filepath: Path, contract_path: Path | None = None, check_chain: bool = False
) -> ValidationResult:
    """Validate a single DSP file."""
    result = ValidationResult(str(filepath))

    try:
        with open(filepath) as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        result.error(f"Invalid JSON: {e}")
        return result
    except FileNotFoundError:
        result.error(f"File not found: {filepath}")
        return result

    # Handle audit trail (array of events)
    if isinstance(data, list):
        if check_chain:
            validate_audit_chain(data, result)
        for i, event in enumerate(data):
            event_result = ValidationResult(f"{filepath}[{i}]")
            validate_schema(event, event_result)
            result.errors.extend(event_result.errors)
            result.warnings.extend(event_result.warnings)
        return result

    # Single message
    validate_schema(data, result)

    schema_id = detect_schema(data)

    # Layer-specific semantic checks
    if schema_id == "https://dssp.dev/schema/manifest/v0.1":
        validate_manifest_pii(data, result)

    elif schema_id == "https://dssp.dev/schema/result/v0.1":
        contract = None
        if contract_path:
            try:
                with open(contract_path) as f:
                    contract = json.load(f)
            except (json.JSONDecodeError, FileNotFoundError) as e:
                result.warn(f"Could not load contract for compliance check: {e}")

        validate_result_pii(data, contract, result)
        if contract:
            validate_result_contract_compliance(data, contract, result)
            validate_numeric_precision(data, contract, result)
            validate_sub_agent_chain(data, contract, result)

    return result


def validate_directory(
    dirpath: Path, check_chain: bool = True
) -> list[ValidationResult]:
    """Validate all JSON files in a directory."""
    results = []
    contract_path = None

    # Find the contract file first
    for f in dirpath.glob("contract*.json"):
        contract_path = f
        break

    for filepath in sorted(dirpath.glob("*.json")):
        is_audit = "audit" in filepath.name
        r = validate_file(
            filepath,
            contract_path=contract_path if "result" in filepath.name else None,
            check_chain=is_audit and check_chain,
        )
        results.append(r)

    return results


def main() -> int:
    parser = argparse.ArgumentParser(
        description="DSSP Reference Validator — validates messages against DSSP schemas"
    )
    parser.add_argument("path", help="JSON file or directory to validate")
    parser.add_argument(
        "--contract", help="Contract file for result compliance checking"
    )
    parser.add_argument(
        "--check-chain", action="store_true", help="Verify audit chain integrity"
    )
    parser.add_argument(
        "--all", action="store_true", help="Validate all JSON files in directory"
    )
    parser.add_argument(
        "--strict", action="store_true", help="Treat warnings as errors"
    )

    args = parser.parse_args()
    path = Path(args.path)

    if args.all or path.is_dir():
        results = validate_directory(path, check_chain=True)
    else:
        contract_path = Path(args.contract) if args.contract else None
        results = [
            validate_file(
                path, contract_path=contract_path, check_chain=args.check_chain
            )
        ]

    all_passed = True
    for r in results:
        print(r.summary())
        if not r.passed:
            all_passed = False
        if args.strict and r.warnings:
            all_passed = False

    print(f"\n{'=' * 60}")
    total = len(results)
    passed = sum(1 for r in results if r.passed)
    print(f"  Total: {total} files | Passed: {passed} | Failed: {total - passed}")
    print(f"{'=' * 60}")

    return 0 if all_passed else 1


if __name__ == "__main__":
    sys.exit(main())
