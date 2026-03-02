"""Tests for the sidecar verifier."""

import pytest
from dsp_sidecar.monitor import MonitorEvidence, NetworkConnection
from dsp_sidecar.verifier import SidecarVerifier


@pytest.fixture
def verifier():
    return SidecarVerifier()


def _make_evidence(
    connections: list[tuple[str, int]] | None = None,
    egress_bytes: int = 0,
    peak_memory: int = 0,
) -> MonitorEvidence:
    evidence = MonitorEvidence(
        session_id="ps-test",
        monitoring_start="2026-01-01T00:00:00Z",
        monitoring_end="2026-01-01T00:05:00Z",
    )
    for addr, port in (connections or []):
        evidence.network_connections.append(NetworkConnection(
            timestamp="2026-01-01T00:01:00Z",
            remote_address=addr,
            remote_port=port,
            protocol="tcp",
            direction="outbound",
        ))
        evidence.unique_destinations.add(f"{addr}:{port}")
    evidence.total_egress_bytes = egress_bytes
    evidence.peak_memory_bytes = peak_memory
    return evidence


class TestNetworkVerification:
    def test_matching_destinations_pass(self, verifier):
        evidence = _make_evidence(connections=[("10.0.0.1", 443)])
        claims = {"network_destinations": ["10.0.0.1:443"]}
        result = verifier.verify(evidence, claims)
        assert result.passed is True
        assert len(result.mismatches) == 0

    def test_undeclared_destination_fails(self, verifier):
        evidence = _make_evidence(connections=[
            ("10.0.0.1", 443),
            ("evil.com", 8080),
        ])
        claims = {"network_destinations": ["10.0.0.1:443"]}
        result = verifier.verify(evidence, claims)
        assert result.passed is False
        assert any(m["type"] == "network_destination_undeclared" for m in result.mismatches)

    def test_zero_claimed_connections_with_observed_fails(self, verifier):
        evidence = _make_evidence(connections=[("10.0.0.1", 443)])
        claims = {"network_destinations": []}
        result = verifier.verify(evidence, claims)
        assert result.passed is False
        assert any(m["type"] == "undeclared_connections" for m in result.mismatches)

    def test_no_connections_passes(self, verifier):
        evidence = _make_evidence()
        claims = {"network_destinations": []}
        result = verifier.verify(evidence, claims)
        assert result.passed is True


class TestEgressVerification:
    def test_matching_egress_passes(self, verifier):
        evidence = _make_evidence(egress_bytes=1000)
        claims = {"network_egress_bytes": 1000}
        result = verifier.verify(evidence, claims)
        assert result.passed is True

    def test_excessive_egress_fails(self, verifier):
        evidence = _make_evidence(egress_bytes=10_000_000)
        claims = {"network_egress_bytes": 1000}
        result = verifier.verify(evidence, claims)
        assert result.passed is False
        assert any(m["type"] == "egress_bytes_mismatch" for m in result.mismatches)


class TestMemoryVerification:
    def test_reasonable_memory_passes(self, verifier):
        evidence = _make_evidence(peak_memory=100_000_000)
        claims = {"memory_peak_bytes": 100_000_000}
        result = verifier.verify(evidence, claims)
        assert result.passed is True

    def test_excessive_memory_fails(self, verifier):
        evidence = _make_evidence(peak_memory=500_000_000)
        claims = {"memory_peak_bytes": 100_000_000}
        result = verifier.verify(evidence, claims)
        assert result.passed is False
        assert any(m["type"] == "memory_peak_mismatch" for m in result.mismatches)
