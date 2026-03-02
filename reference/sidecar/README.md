# DSP Sidecar Verifier

Reference implementation of the sidecar verifier defined in DSP spec section 4.7.

## Overview

The sidecar verifier is an independent co-processor that runs in a separate
enclave alongside a DSP agent. It monitors the agent's actual behavior and
compares it against the agent's self-reported claims in the result attestation.

The sidecar monitors:

- **Network I/O** -- active TCP/UDP connections, remote destinations, bytes sent/received
- **Memory allocation** -- RSS, VMS, and peak memory usage over time
- **DNS queries** -- hostnames resolved and their IP addresses
- **Syscalls** -- (placeholder for production eBPF-based monitoring)

## Running

### Standalone

```bash
pip install -e ".[dev]"
dsp-sidecar --session-id ps-abc123 --agent-pid 12345 --gateway http://localhost:8080
```

### Docker

```bash
docker build -t dsp-sidecar .
docker run --pid=host dsp-sidecar \
    --session-id ps-abc123 \
    --agent-pid 12345 \
    --gateway http://gateway:8080
```

### With Docker Compose

Add alongside the agent service in your `docker-compose.yml`:

```yaml
sidecar:
  build: ./reference/sidecar
  pid: "service:agent"
  command: ["--session-id", "ps-abc123", "--agent-pid", "1", "--gateway", "http://gateway:8080"]
```

## Mismatch Detection

The verifier performs four categories of checks:

| Check | Severity | Event Type |
|-------|----------|------------|
| Undeclared network destinations | critical | `sidecar.network_mismatch` |
| Egress bytes exceed claimed amount | high | `sidecar.network_mismatch` |
| Peak memory exceeds claimed amount (>1.5x) | medium | `sidecar.anomaly_detected` |
| Agent claims zero connections but sidecar observes traffic | critical | `sidecar.network_mismatch` |

When a mismatch is detected, the verifier:

1. Marks the verification as **failed**
2. Emits a `sidecar.network_mismatch` or `sidecar.anomaly_detected` audit event to the gateway
3. Includes full details (claimed vs observed values) in the verification output

## Verification Output

The verifier produces a JSON report:

```json
{
  "verification": {
    "session_id": "ps-abc123",
    "verified_at": "2026-01-01T00:05:00Z",
    "passed": false,
    "mismatches": [
      {
        "type": "network_destination_undeclared",
        "severity": "critical",
        "description": "Agent made connections to 1 undeclared destination(s)",
        "undeclared": ["evil.com:8080"],
        "audit_event_type": "sidecar.network_mismatch"
      }
    ],
    "warnings": []
  },
  "evidence_summary": {
    "network_connections": 2,
    "unique_destinations": 2,
    "memory_snapshots": 300,
    "peak_memory_bytes": 104857600,
    "total_egress_bytes": 1048576,
    "anomalies": 0
  }
}
```

## Tests

```bash
pip install -e ".[dev]"
pytest tests/
```
