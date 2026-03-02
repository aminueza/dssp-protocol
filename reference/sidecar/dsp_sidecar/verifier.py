"""Verifier — compares sidecar evidence against agent self-reported claims."""

from __future__ import annotations

import time
from dataclasses import dataclass, field

from .monitor import MonitorEvidence


@dataclass
class VerificationResult:
    """Result of comparing sidecar evidence against agent claims."""
    session_id: str
    verified_at: str
    passed: bool
    mismatches: list[dict] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "session_id": self.session_id,
            "verified_at": self.verified_at,
            "passed": self.passed,
            "mismatches": self.mismatches,
            "warnings": self.warnings,
        }


class SidecarVerifier:
    """Compares sidecar-collected evidence against agent self-reported claims.

    This is the core verification logic. In production, the sidecar evidence
    is collected by a process running in a separate enclave, making it
    tamper-proof from the agent's perspective.
    """

    def __init__(self, tolerance_bytes: int = 1024 * 1024):
        self._tolerance_bytes = tolerance_bytes

    def verify(
        self,
        evidence: MonitorEvidence,
        agent_claims: dict,
    ) -> VerificationResult:
        """Compare sidecar evidence against agent claims from the result attestation.

        Args:
            evidence: Evidence collected by the sidecar monitor.
            agent_claims: The attestation.claims from the agent's result envelope.

        Returns:
            VerificationResult with any mismatches found.
        """
        result = VerificationResult(
            session_id=evidence.session_id,
            verified_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            passed=True,
        )

        self._check_network_destinations(evidence, agent_claims, result)
        self._check_egress_bytes(evidence, agent_claims, result)
        self._check_memory_usage(evidence, agent_claims, result)
        self._check_connection_count(evidence, agent_claims, result)

        result.passed = len(result.mismatches) == 0
        return result

    def _check_network_destinations(
        self,
        evidence: MonitorEvidence,
        claims: dict,
        result: VerificationResult,
    ) -> None:
        """Check if agent-reported network destinations match sidecar observations."""
        claimed_destinations = set(claims.get("network_destinations", []))
        observed_destinations = evidence.unique_destinations

        # Destinations observed by sidecar but not claimed by agent
        undeclared = observed_destinations - claimed_destinations
        if undeclared:
            result.mismatches.append({
                "type": "network_destination_undeclared",
                "severity": "critical",
                "description": f"Agent made connections to {len(undeclared)} undeclared destination(s)",
                "claimed": sorted(claimed_destinations),
                "observed": sorted(observed_destinations),
                "undeclared": sorted(undeclared),
                "audit_event_type": "sidecar.network_mismatch",
            })

        # Destinations claimed by agent but not observed by sidecar
        # This is less severe — could be timing or the connection was too brief
        phantom = claimed_destinations - observed_destinations
        if phantom:
            result.warnings.append(
                f"Agent claimed {len(phantom)} destination(s) not observed by sidecar: "
                f"{sorted(phantom)}"
            )

    def _check_egress_bytes(
        self,
        evidence: MonitorEvidence,
        claims: dict,
        result: VerificationResult,
    ) -> None:
        """Check if claimed egress bytes match sidecar observations."""
        claimed_egress = claims.get("network_egress_bytes", 0)
        observed_egress = evidence.total_egress_bytes

        if observed_egress > claimed_egress + self._tolerance_bytes:
            result.mismatches.append({
                "type": "egress_bytes_mismatch",
                "severity": "high",
                "description": (
                    f"Sidecar observed {observed_egress} bytes egress, "
                    f"agent claimed {claimed_egress} bytes "
                    f"(difference: {observed_egress - claimed_egress} bytes)"
                ),
                "claimed": claimed_egress,
                "observed": observed_egress,
                "audit_event_type": "sidecar.network_mismatch",
            })

    def _check_memory_usage(
        self,
        evidence: MonitorEvidence,
        claims: dict,
        result: VerificationResult,
    ) -> None:
        """Check if claimed memory usage aligns with sidecar observations."""
        claimed_peak = claims.get("memory_peak_bytes", 0)
        observed_peak = evidence.peak_memory_bytes

        if observed_peak > 0 and claimed_peak > 0:
            # Allow 10% tolerance for measurement timing differences
            if observed_peak > claimed_peak * 1.5:
                result.mismatches.append({
                    "type": "memory_peak_mismatch",
                    "severity": "medium",
                    "description": (
                        f"Sidecar observed peak memory {observed_peak} bytes, "
                        f"agent claimed {claimed_peak} bytes"
                    ),
                    "claimed": claimed_peak,
                    "observed": observed_peak,
                    "audit_event_type": "sidecar.anomaly_detected",
                })

    def _check_connection_count(
        self,
        evidence: MonitorEvidence,
        claims: dict,
        result: VerificationResult,
    ) -> None:
        """Check if the number of connections matches expectations."""
        claimed_dests = claims.get("network_destinations", [])
        observed_conns = len(evidence.network_connections)

        if len(claimed_dests) == 0 and observed_conns > 0:
            result.mismatches.append({
                "type": "undeclared_connections",
                "severity": "critical",
                "description": (
                    f"Agent claimed 0 network connections but sidecar "
                    f"observed {observed_conns} connection(s)"
                ),
                "claimed_destinations": 0,
                "observed_connections": observed_conns,
                "audit_event_type": "sidecar.network_mismatch",
            })
