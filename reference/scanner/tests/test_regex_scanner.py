"""Tests for the regex scanner."""

import pytest
from dsp_scanner.regex_scanner import RegexScanner


@pytest.fixture
def scanner():
    return RegexScanner()


def _make_result(fields: dict) -> dict:
    """Create a minimal DSP result envelope with the given fields."""
    return {
        "extractions": [
            {
                "source_document_id": "doc-test",
                "fields": fields,
            }
        ]
    }


class TestRegexScanner:
    def test_clean_result_passes(self, scanner):
        result = _make_result({"balance": 1247832.50, "currency": "EUR"})
        verdict = scanner.scan(result)
        assert verdict.passed is True
        assert len(verdict.findings) == 0

    def test_detects_ssn(self, scanner):
        result = _make_result({"tax_id": "123-45-6789"})
        verdict = scanner.scan(result)
        assert verdict.passed is False
        assert any(f.entity_type == "SSN" for f in verdict.findings)

    def test_detects_email(self, scanner):
        result = _make_result({"contact": "john@example.com"})
        verdict = scanner.scan(result)
        assert verdict.passed is False
        assert any(f.entity_type == "EMAIL" for f in verdict.findings)

    def test_detects_iban(self, scanner):
        result = _make_result({"account": "NL91ABNA0417164300"})
        verdict = scanner.scan(result)
        assert verdict.passed is False
        assert any(f.entity_type == "IBAN" for f in verdict.findings)

    def test_detects_credit_card(self, scanner):
        result = _make_result({"card": "4111111111111111"})
        verdict = scanner.scan(result)
        assert verdict.passed is False
        assert any(f.entity_type == "CREDIT_CARD" for f in verdict.findings)

    def test_allowed_field_not_flagged(self, scanner):
        result = _make_result({"account": "NL91ABNA0417164300"})
        contract = {
            "restrictions": {
                "result_policy": {
                    "pii_redaction_rules": {
                        "IBAN": "allow"
                    }
                }
            }
        }
        verdict = scanner.scan(result, contract)
        # IBAN should not be flagged when explicitly allowed
        assert not any(f.entity_type == "IBAN" for f in verdict.findings)

    def test_verdict_format(self, scanner):
        result = _make_result({"balance": 100.00})
        verdict = scanner.scan(result)
        d = verdict.to_dict()
        assert d["scanner_type"] == "regex"
        assert "scanner_version" in d
        assert "passed" in d
        assert "findings" in d
        assert "scan_duration_ms" in d
