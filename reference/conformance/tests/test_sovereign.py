"""DSP Sovereign — Data sovereignty tests."""

import pytest


@pytest.mark.sovereign
class TestDataResidency:
    def test_owner_has_data_residency(self, sample_manifest):
        """Owner MUST declare data residency zone."""
        owner = sample_manifest.get("owner", {})
        assert "data_residency" in owner, \
            "Owner must declare data_residency"

    def test_owner_has_jurisdiction(self, sample_manifest):
        """Owner MUST declare jurisdiction."""
        owner = sample_manifest.get("owner", {})
        assert "jurisdiction" in owner, \
            "Owner must declare jurisdiction"


@pytest.mark.sovereign
class TestGatewayVisibility:
    def test_gateway_visibility_configured(self, sample_contract):
        """Contract SHOULD configure gateway visibility."""
        visibility = (sample_contract.get("restrictions", {})
                     .get("gateway_visibility", {}))
        if not visibility:
            pytest.skip("No gateway visibility configured")

        valid_manifest_opts = {"full", "summary_only", "none"}
        valid_result_opts = {"full", "metadata_only", "verdict_only", "none"}
        valid_audit_opts = {"full", "summary_only", "none"}

        if "manifests" in visibility:
            assert visibility["manifests"] in valid_manifest_opts
        if "results" in visibility:
            assert visibility["results"] in valid_result_opts
        if "audit_events" in visibility:
            assert visibility["audit_events"] in valid_audit_opts

    def test_cross_engagement_correlation_disabled(self, sample_contract):
        """Cross-engagement correlation SHOULD be disabled for regulated data."""
        visibility = (sample_contract.get("restrictions", {})
                     .get("gateway_visibility", {}))
        if not visibility:
            pytest.skip("No gateway visibility configured")

        assert visibility.get("cross_engagement_correlation") is False, \
            "Cross-engagement correlation should be disabled for regulated data"
