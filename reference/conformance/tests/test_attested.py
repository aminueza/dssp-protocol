"""DSSP Attested — Attestation verification tests."""

import pytest


@pytest.mark.attested
class TestAttestationVerification:
    def test_result_has_attestation(self, sample_result):
        """Result MUST include attestation proof."""
        assert "attestation" in sample_result
        att = sample_result["attestation"]
        assert "enclave_type" in att
        assert "measurement" in att
        assert "agent_hash" in att

    def test_enclave_type_is_valid(self, sample_result):
        """Enclave type MUST be a known TEE type (not sandbox for pii-high)."""
        att = sample_result.get("attestation", {})
        valid_types = {"sgx", "sev-snp", "tdx", "nitro", "cca", "sandbox"}
        assert att.get("enclave_type") in valid_types

    def test_agent_hash_matches_contract(self, sample_result, sample_contract):
        """Agent hash in result MUST match contract requirement."""
        result_hash = sample_result.get("attestation", {}).get("agent_hash", {})
        contract_hash = sample_contract.get("consumer", {}).get("agent_hash", {})
        if contract_hash:
            assert result_hash.get("value") == contract_hash.get("value"), (
                "Agent hash mismatch between result and contract"
            )

    def test_sandbox_rejected_for_pii_high(self, sample_result, sample_contract):
        """Sandbox enclave MUST be rejected for pii-high+ documents."""
        att = sample_result.get("attestation", {})
        if att.get("enclave_type") == "sandbox":
            # Check if any documents are pii-high or above
            high_sensitivity = {"pii-high", "pii-critical"}
            contract_filter = sample_contract.get("permissions", {}).get(
                "document_filter", {}
            )
            max_sensitivity = contract_filter.get("max_sensitivity", "")
            if max_sensitivity in high_sensitivity:
                pytest.fail("Sandbox enclave used for pii-high+ documents")


@pytest.mark.attested
class TestEndOfSessionAttestation:
    def test_eos_attestation_present(self, sample_result):
        """End-of-session attestation SHOULD be present."""
        if "end_of_session_attestation" in sample_result:
            eos = sample_result["end_of_session_attestation"]
            assert "measurement" in eos
            assert "timestamp" in eos

    def test_eos_measurement_matches_start(self, sample_result):
        """End-of-session measurement MUST match start measurement."""
        if "end_of_session_attestation" not in sample_result:
            pytest.skip("No end-of-session attestation")
        eos = sample_result["end_of_session_attestation"]
        start = sample_result.get("attestation", {}).get("measurement")
        if start and eos.get("measurement"):
            assert eos["measurement"] == start, (
                "End-of-session measurement mismatch — possible tampering"
            )
