"""DSP Sidecar Verifier — main entry point.

Runs as a separate process alongside the agent. In production,
this would run in a separate enclave.

Usage:
    dsp-sidecar --session-id ps-abc123 --agent-pid 12345 --gateway http://localhost:8080
"""

from __future__ import annotations

import argparse
import json
import signal
import sys
import time

import requests

from .monitor import AgentMonitor
from .verifier import SidecarVerifier


def main() -> None:
    parser = argparse.ArgumentParser(description="DSP Sidecar Verifier")
    parser.add_argument("--session-id", required=True, help="DSP session ID to monitor")
    parser.add_argument("--agent-pid", type=int, help="Agent process PID to monitor")
    parser.add_argument("--gateway", default="http://localhost:8080", help="Gateway URL")
    parser.add_argument("--poll-interval", type=float, default=1.0, help="Monitoring poll interval (seconds)")
    parser.add_argument("--output", help="Output file for verification result (default: stdout)")
    args = parser.parse_args()

    print(f"[sidecar] Starting verifier for session {args.session_id}", flush=True)
    if args.agent_pid:
        print(f"[sidecar] Monitoring agent PID {args.agent_pid}", flush=True)

    # Start monitoring
    monitor = AgentMonitor(
        session_id=args.session_id,
        agent_pid=args.agent_pid,
    )
    monitor._poll_interval = args.poll_interval
    monitor.start()

    # Handle shutdown signal
    def shutdown(signum, frame):
        print("[sidecar] Received shutdown signal, stopping monitor...", flush=True)
        evidence = monitor.stop()
        _verify_and_report(evidence, args)
        sys.exit(0)

    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)

    # Monitor until agent completes or we're stopped
    print("[sidecar] Monitoring active. Waiting for session to complete...", flush=True)
    try:
        while True:
            # Check if session is still active
            try:
                resp = requests.get(
                    f"{args.gateway}/v0.1/sessions/{args.session_id}",
                    timeout=5,
                )
                if resp.status_code == 200:
                    session = resp.json()
                    status = session.get("status", "")
                    if status in ("completed", "failed", "terminated"):
                        print(f"[sidecar] Session {status}. Stopping monitor.", flush=True)
                        break
            except requests.ConnectionError:
                pass

            time.sleep(args.poll_interval)
    except KeyboardInterrupt:
        pass

    evidence = monitor.stop()
    _verify_and_report(evidence, args)


def _verify_and_report(evidence, args) -> None:
    """Verify evidence against agent claims and report results."""
    # Try to get the agent's result to compare claims
    agent_claims = {}
    try:
        resp = requests.get(
            f"{args.gateway}/v0.1/sessions/{args.session_id}/result",
            timeout=5,
        )
        if resp.status_code == 200:
            result = resp.json()
            agent_claims = result.get("attestation", {}).get("claims", {})
    except Exception:
        pass

    # Verify
    verifier = SidecarVerifier()
    verification = verifier.verify(evidence, agent_claims)

    output = {
        "verification": verification.to_dict(),
        "evidence_summary": {
            "network_connections": len(evidence.network_connections),
            "unique_destinations": len(evidence.unique_destinations),
            "memory_snapshots": len(evidence.memory_snapshots),
            "peak_memory_bytes": evidence.peak_memory_bytes,
            "total_egress_bytes": evidence.total_egress_bytes,
            "anomalies": len(evidence.anomalies),
        },
    }

    output_json = json.dumps(output, indent=2)

    if args.output:
        with open(args.output, "w") as f:
            f.write(output_json)
        print(f"[sidecar] Verification result written to {args.output}", flush=True)
    else:
        print(output_json)

    # Report mismatches to gateway as audit events
    for mismatch in verification.mismatches:
        try:
            audit_event = {
                "event_type": mismatch.get("audit_event_type", "sidecar.anomaly_detected"),
                "actor": {"type": "system", "agent_id": "dsp-sidecar-verifier"},
                "subject": {"type": "session", "session_id": args.session_id},
                "action": {"reason": mismatch["description"]},
                "outcome": {
                    "status": "failure",
                    "error_message": mismatch["description"],
                },
            }
            requests.post(
                f"{args.gateway}/v0.1/audit/events",
                json=audit_event,
                timeout=5,
            )
        except Exception:
            pass

    status = "PASSED" if verification.passed else "FAILED"
    print(f"[sidecar] Verification {status}: {len(verification.mismatches)} mismatch(es)", flush=True)


if __name__ == "__main__":
    main()
