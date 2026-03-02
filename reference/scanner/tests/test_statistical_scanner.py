"""Tests for the statistical scanner."""

from dsp_scanner.statistical_scanner import StatisticalScanner


def _make_result(fields: dict) -> dict:
    return {"extractions": [{"source_document_id": "doc-test", "fields": fields}]}


class TestStatisticalScanner:
    def test_clean_values_pass(self):
        scanner = StatisticalScanner(max_decimal_places=2)
        result = _make_result({"balance": 1247832.50, "amount": 500.00})
        verdict = scanner.scan(result)
        assert verdict.passed is True

    def test_excess_decimal_places_detected(self):
        scanner = StatisticalScanner(max_decimal_places=2)
        result = _make_result({"balance": 1247832.5031742})
        verdict = scanner.scan(result)
        assert verdict.passed is False
        assert any(f.entity_type == "PRECISION_VIOLATION" for f in verdict.findings)

    def test_confidence_score_precision(self):
        scanner = StatisticalScanner(max_decimal_places=2)
        result = {
            "extractions": [{
                "source_document_id": "doc-test",
                "confidence": 0.9700000000000001,
                "fields": {},
            }]
        }
        verdict = scanner.scan(result)
        assert verdict.passed is False

    def test_policy_from_contract(self):
        scanner = StatisticalScanner()
        result = _make_result({"balance": 1247832.5031742})
        contract = {
            "restrictions": {
                "result_policy": {
                    "numeric_precision_policy": {
                        "max_decimal_places": 8  # Allow more precision
                    }
                }
            }
        }
        verdict = scanner.scan(result, contract)
        assert verdict.passed is True  # 7 decimal places < 8 allowed
