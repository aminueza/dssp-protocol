"""DSP AI-Safe — AI-specific safety tests."""

import pytest


@pytest.mark.ai_safe
class TestAgentTypeScanning:
    def test_llm_freeform_requires_ner(self, sample_contract):
        """llm_freeform agents MUST have NER scanning enabled."""
        agent_type = sample_contract.get("consumer", {}).get("agent_type")
        if agent_type != "llm_freeform":
            pytest.skip("Not an llm_freeform contract")
        scanning = sample_contract.get("restrictions", {}).get("result_scanning", {})
        assert scanning.get("enabled") is True, \
            "Result scanning MUST be enabled for llm_freeform"
        scanners = scanning.get("required_scanners", [])
        assert "ner" in scanners, \
            "NER scanner MUST be required for llm_freeform"
        assert "llm_output_filter" in scanners, \
            "llm_output_filter scanner MUST be required for llm_freeform"

    def test_ml_structured_requires_ner(self, sample_contract):
        """ml_structured agents MUST have at least regex + ner scanning."""
        agent_type = sample_contract.get("consumer", {}).get("agent_type")
        if agent_type != "ml_structured":
            pytest.skip("Not an ml_structured contract")
        scanning = sample_contract.get("restrictions", {}).get("result_scanning", {})
        scanners = scanning.get("required_scanners", [])
        assert "regex" in scanners, "regex scanner MUST be required for ml_structured"
        assert "ner" in scanners, "ner scanner MUST be required for ml_structured"


@pytest.mark.ai_safe
class TestPrivacyBudget:
    def test_llm_freeform_has_privacy_budget(self, sample_contract):
        """llm_freeform agents MUST have a privacy budget."""
        agent_type = sample_contract.get("consumer", {}).get("agent_type")
        if agent_type != "llm_freeform":
            pytest.skip("Not an llm_freeform contract")
        budget = sample_contract.get("restrictions", {}).get("privacy_budget", {})
        assert budget, "Privacy budget REQUIRED for llm_freeform"


@pytest.mark.ai_safe
class TestSubAgentChain:
    def test_sub_agent_chain_declared(self, sample_result, sample_contract):
        """If sub-agents were used, the chain MUST be declared."""
        chain = (sample_result.get("attestation", {})
                .get("claims", {})
                .get("sub_agent_chain", []))
        if not chain:
            pytest.skip("No sub-agent chain")

        policy = sample_contract.get("consumer", {}).get("sub_agent_policy", {})
        if not policy.get("allowed", True):
            pytest.fail("Sub-agents used but not allowed by policy")

        max_steps = policy.get("max_steps", float("inf"))
        assert len(chain) <= max_steps, \
            f"Sub-agent chain has {len(chain)} steps, max is {max_steps}"

    def test_no_undeclared_llm_in_chain(self, sample_result, sample_contract):
        """LLM sub-agents MUST NOT appear if llm_sub_agent_allowed is false."""
        chain = (sample_result.get("attestation", {})
                .get("claims", {})
                .get("sub_agent_chain", []))
        policy = sample_contract.get("consumer", {}).get("sub_agent_policy", {})

        if policy.get("llm_sub_agent_allowed", True):
            pytest.skip("LLM sub-agents are allowed")

        for step in chain:
            assert step.get("agent_type") != "llm_freeform", \
                f"Undeclared LLM sub-agent at step {step.get('step_index')}"


@pytest.mark.ai_safe
class TestNumericPrecision:
    def test_numeric_precision_compliance(self, sample_result, sample_contract):
        """Numeric fields MUST comply with precision policy."""
        policy = (sample_contract.get("restrictions", {})
                 .get("result_policy", {})
                 .get("numeric_precision_policy", {}))
        if not policy:
            pytest.skip("No numeric precision policy")

        max_dp = policy.get("max_decimal_places", 100)

        for extraction in sample_result.get("extractions", []):
            for key, value in extraction.get("fields", {}).items():
                if isinstance(value, float):
                    s = f"{value:.20g}"
                    if "." in s:
                        dp = len(s.split(".")[1].rstrip("0"))
                        assert dp <= max_dp, \
                            f"Field '{key}' has {dp} decimal places, max is {max_dp}"
