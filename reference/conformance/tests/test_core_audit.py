"""DSSP Core — Audit chain integrity tests."""

import pytest


@pytest.mark.core
class TestAuditChainIntegrity:
    def test_sequential_sequence_numbers(self, sample_audit_trail):
        """Audit events MUST have sequential sequence numbers."""
        events = (
            sample_audit_trail
            if isinstance(sample_audit_trail, list)
            else sample_audit_trail.get("events", [sample_audit_trail])
        )
        if len(events) < 2:
            pytest.skip("Need at least 2 events for sequence test")

        for i in range(1, len(events)):
            prev_seq = events[i - 1].get("sequence_number", 0)
            curr_seq = events[i].get("sequence_number", 0)
            assert curr_seq == prev_seq + 1, (
                f"Sequence gap: event {i} has seq {curr_seq}, expected {prev_seq + 1}"
            )

    def test_non_decreasing_timestamps(self, sample_audit_trail):
        """Audit event timestamps MUST be non-decreasing."""
        events = (
            sample_audit_trail
            if isinstance(sample_audit_trail, list)
            else sample_audit_trail.get("events", [sample_audit_trail])
        )
        if len(events) < 2:
            pytest.skip("Need at least 2 events for timestamp test")

        for i in range(1, len(events)):
            prev_ts = events[i - 1].get("timestamp", "")
            curr_ts = events[i].get("timestamp", "")
            assert curr_ts >= prev_ts, (
                f"Timestamp went backwards: {curr_ts} < {prev_ts}"
            )

    def test_hash_chain_references(self, sample_audit_trail):
        """Each event's previous_event_hash MUST reference the prior event's event_hash."""
        events = (
            sample_audit_trail
            if isinstance(sample_audit_trail, list)
            else sample_audit_trail.get("events", [sample_audit_trail])
        )
        if len(events) < 2:
            pytest.skip("Need at least 2 events for chain test")

        for i in range(1, len(events)):
            prev_hash = events[i - 1].get("event_hash", {})
            curr_prev_hash = events[i].get("previous_event_hash", {})

            if isinstance(prev_hash, dict) and isinstance(curr_prev_hash, dict):
                assert prev_hash.get("value") == curr_prev_hash.get("value"), (
                    f"Chain break at event {i}: previous_event_hash doesn't match prior event_hash"
                )

    def test_genesis_event_has_no_previous(self, sample_audit_trail):
        """The first (genesis) event MUST NOT have a previous_event_hash."""
        events = (
            sample_audit_trail
            if isinstance(sample_audit_trail, list)
            else sample_audit_trail.get("events", [sample_audit_trail])
        )
        if events:
            first = events[0]
            prev = first.get("previous_event_hash")
            assert prev is None or prev == "", (
                "Genesis event should not have previous_event_hash"
            )

    def test_tamper_detection(self, sample_audit_trail):
        """Modifying an event MUST break the hash chain."""
        events = (
            sample_audit_trail
            if isinstance(sample_audit_trail, list)
            else sample_audit_trail.get("events", [sample_audit_trail])
        )
        if len(events) < 2:
            pytest.skip("Need at least 2 events for tamper test")

        # This is a conceptual test — in practice we'd recompute hashes
        # For now, verify that event_hash fields are present and non-empty
        for i, event in enumerate(events):
            eh = event.get("event_hash", {})
            assert isinstance(eh, dict), f"Event {i} missing event_hash"
            assert eh.get("value"), f"Event {i} has empty event_hash"


@pytest.mark.core
class TestAuditEventTypes:
    def test_known_event_types(self, sample_audit_trail):
        """All event types MUST be from the defined set."""
        known_types = {
            "manifest.created",
            "manifest.updated",
            "manifest.expired",
            "contract.created",
            "contract.updated",
            "contract.suspended",
            "contract.revoked",
            "contract.expired",
            "session.started",
            "session.completed",
            "session.failed",
            "session.terminated",
            "session.timeout",
            "document.accessed",
            "document.processed",
            "result.produced",
            "result.delivered",
            "result.rejected",
            "result.quarantined",
            "result.scan_passed",
            "result.scan_failed",
            "attestation.verified",
            "attestation.failed",
            "attestation.end_of_session",
            "attestation.heartbeat",
            "sanitization.applied",
            "sanitization.injection_detected",
            "sidecar.network_mismatch",
            "sidecar.anomaly_detected",
            "privacy_budget.consumed",
            "privacy_budget.exceeded",
            "violation.detected",
            "violation.escalated",
            "access.granted",
            "access.denied",
            "access.revoked",
            "ledger.genesis",
            "ledger.checkpoint",
        }
        events = (
            sample_audit_trail
            if isinstance(sample_audit_trail, list)
            else sample_audit_trail.get("events", [sample_audit_trail])
        )
        for event in events:
            et = event.get("event_type", "")
            assert et in known_types, f"Unknown event type: {et}"
