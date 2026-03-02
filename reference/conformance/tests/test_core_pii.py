"""DSSP Core — PII safety tests."""

import re
import pytest


PII_PATTERNS = {
    "SSN": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    "EMAIL": re.compile(r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b"),
    "CREDIT_CARD": re.compile(r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14})\b"),
    "IBAN": re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{4,30}\b"),
    "PHONE": re.compile(
        r"\b(?:\+?1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}\b"
    ),
}


def _extract_all_strings(obj, path="") -> list[tuple[str, str]]:
    """Extract all string values from a nested object with their paths."""
    results = []
    if isinstance(obj, str):
        results.append((path, obj))
    elif isinstance(obj, dict):
        for k, v in obj.items():
            results.extend(_extract_all_strings(v, f"{path}.{k}"))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            results.extend(_extract_all_strings(v, f"{path}[{i}]"))
    return results


@pytest.mark.core
class TestManifestPII:
    def test_manifest_contains_no_pii(self, sample_manifest):
        """Manifest MUST NOT contain PII values."""
        strings = _extract_all_strings(sample_manifest)
        for path, value in strings:
            for pii_type, pattern in PII_PATTERNS.items():
                assert not pattern.search(value), (
                    f"PII ({pii_type}) found in manifest at {path}: {value[:50]}"
                )

    def test_document_ids_are_opaque(self, sample_manifest):
        """Document IDs MUST be opaque (not filenames)."""
        for doc in sample_manifest.get("documents", []):
            doc_id = doc.get("document_id", "")
            assert not doc_id.endswith((".pdf", ".docx", ".xlsx", ".csv")), (
                f"Document ID appears to be a filename: {doc_id}"
            )
            assert doc_id.startswith("doc-"), (
                f"Document ID should use 'doc-' prefix: {doc_id}"
            )


@pytest.mark.core
class TestResultPII:
    def test_suppressed_fields_absent(self, sample_result, sample_contract):
        """Fields with 'suppress' redaction MUST NOT appear in results."""
        rules = (
            sample_contract.get("restrictions", {})
            .get("result_policy", {})
            .get("pii_redaction_rules", {})
        )
        suppressed = {k for k, v in rules.items() if v == "suppress"}

        for extraction in sample_result.get("extractions", []):
            for field_name in extraction.get("fields", {}):
                assert field_name not in suppressed, (
                    f"Suppressed field '{field_name}' found in result"
                )

    def test_masked_fields_are_masked(self, sample_result, sample_contract):
        """Fields with 'mask_last_4' MUST show only last 4 characters."""
        rules = (
            sample_contract.get("restrictions", {})
            .get("result_policy", {})
            .get("pii_redaction_rules", {})
        )
        masked = {k for k, v in rules.items() if v == "mask_last_4"}

        for extraction in sample_result.get("extractions", []):
            fields = extraction.get("fields", {})
            for field_name in masked:
                if field_name in fields:
                    value = str(fields[field_name])
                    if len(value) > 4:
                        prefix = value[:-4]
                        assert all(c == "*" for c in prefix), (
                            f"Field '{field_name}' not properly masked: {value}"
                        )

    def test_pii_report_present(self, sample_result):
        """Result MUST include a PII handling report."""
        assert "pii_report" in sample_result
        report = sample_result["pii_report"]
        assert "compliance_status" in report
        assert report["compliance_status"] in (
            "compliant",
            "violation_detected",
            "unknown",
        )

    def test_result_scan_present(self, sample_result):
        """Result MUST include scan information."""
        assert "result_scan" in sample_result
        scan = sample_result["result_scan"]
        assert "performed" in scan
        assert "overall_passed" in scan
