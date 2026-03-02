"""DSP Core — Contract enforcement tests."""

import pytest


@pytest.mark.core
class TestContractEnforcement:
    def test_result_operations_within_contract(self, sample_result, sample_contract):
        """Result extraction types MUST be within contract-allowed operations."""
        allowed = set(sample_contract.get("permissions", {}).get("operations", []))
        for extraction in sample_result.get("extractions", []):
            ext_type = extraction.get("extraction_type", "")
            # Map extraction types to operations
            type_to_op = {
                "text": "extract_text",
                "key_value": "extract_key_value",
                "table": "extract_tables",
                "classification": "classify_document",
            }
            if ext_type in type_to_op:
                op = type_to_op[ext_type]
                assert op in allowed, \
                    f"Extraction type '{ext_type}' maps to operation '{op}' not in contract"

    def test_contract_has_valid_period(self, sample_contract):
        """Contract MUST have valid_from before valid_until."""
        perms = sample_contract.get("permissions", {})
        valid_from = perms.get("valid_from", "")
        valid_until = perms.get("valid_until", "")
        if valid_from and valid_until:
            assert valid_from < valid_until, \
                f"Contract validity period invalid: {valid_from} >= {valid_until}"

    def test_contract_has_session_limits(self, sample_contract):
        """Contract SHOULD specify session limits."""
        perms = sample_contract.get("permissions", {})
        assert "max_documents_per_session" in perms
        assert "max_concurrent_sessions" in perms
        assert perms["max_documents_per_session"] > 0
        assert perms["max_concurrent_sessions"] > 0


@pytest.mark.core
class TestContractRevocation:
    def test_revoked_contract_has_reason(self, sample_contract):
        """If contract is revoked, it SHOULD have a revocation timestamp."""
        if sample_contract.get("status") == "revoked":
            assert "revoked_at" in sample_contract
