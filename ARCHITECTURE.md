# DSP Reference Architecture

This document describes the reference implementation structure and clarifies
the role of each component.

## Component Map

```
dsp-protocol/
├── spec/                          # SPECIFICATION (normative)
│   ├── dsp-v0.1.md                #   Protocol specification
│   └── dsp-api-v0.1.yaml          #   Wire protocol (OpenAPI 3.1)
│
├── schemas/                       # JSON SCHEMAS (normative)
│   ├── common.schema.json         #   Shared types and definitions
│   ├── manifest.schema.json       #   Layer 1: Document Manifest
│   ├── contract.schema.json       #   Layer 2: Processing Contract
│   ├── result.schema.json         #   Layer 3: Result Envelope
│   ├── audit-event.schema.json    #   Layer 4: Audit Ledger
│   └── storage-binding.schema.json#   Layer 0: Storage Binding
│
├── reference/                     # REFERENCE IMPLEMENTATIONS (informative)
│   ├── gateway/                   #   Gateway server (see below)
│   ├── agent/                     #   Processing agent (Python)
│   ├── scanner/                   #   Result scanner (Python)
│   ├── sidecar/                   #   Sidecar verifier (Python)
│   ├── storage-adapters/minio/    #   MinIO storage adapter (Go)
│   ├── validator/                 #   Schema validator (Python)
│   ├── conformance/               #   Conformance test suite (Python)
│   ├── sandbox/                   #   Docker Compose demo
│   └── test-vectors/              #   Interoperability test vectors
│
└── examples/                      # EXAMPLES (informative)
    └── bank-statement-extraction/  #   Complete lifecycle example
```

## Gateway Implementations

The repository contains two gateway implementations, each serving a
different purpose:

### Go Gateway (`reference/gateway/main.go` + `internal/`)

**Role:** Canonical conformance reference implementation.

This is the primary gateway implementation that conforms to the
`spec/dsp-api-v0.1.yaml` wire protocol specification. It implements:

- All 18 OpenAPI endpoints with correct HTTP methods and paths
- RFC 8785 canonical JSON serialization for Merkle chain hashing
- Full contract enforcement (session limits, agent hash, expiry, PII rules)
- Privacy budget tracking (epsilon-based)
- Sub-agent chain validation
- Numeric precision enforcement
- Pluggable storage adapter interface (MinIO integration)

Use this gateway for:
- Conformance testing
- Interoperability verification
- Production deployment starting point
- SDK development and testing

### Python Gateway (`reference/gateway/main.py`)

**Role:** Demo dashboard and rapid prototyping.

This is a FastAPI-based gateway with a built-in web dashboard that
visualizes the DSP flow in real-time. It provides:

- A polished web UI at `/` showing processing flow, PII reports,
  audit trail, sub-agent chains, and validation results
- `/api/state` endpoint for dashboard polling
- Simpler API surface (fewer endpoints than the full spec)
- Direct MinIO credential pass-through for demo scenarios

Use this gateway for:
- Demos and presentations (the dashboard is excellent for explaining DSP)
- Quick prototyping of new agent types
- Visual debugging of the protocol flow

### Which gateway should I use?

| Use case | Gateway |
|----------|---------|
| Building a DSP-compliant implementation | Go gateway |
| Running conformance tests | Go gateway |
| Giving a demo of DSP | Python gateway |
| Integrating with CI/CD | Go gateway |
| Learning how DSP works | Python gateway (start here) |

The `reference/docker-compose.yml` uses the Python gateway by default
(for the dashboard). The `reference/sandbox/docker-compose.yml` uses the
Go gateway (for conformance).

## Processing Agent (`reference/agent/`)

The reference agent is a Python application with pluggable attestation
backends:

- **simulated** — Fake attestation for development (default)
- **gramine** — Gramine-based SGX attestation (supports both
  gramine-direct simulation and real gramine-sgx)
- **nitro** — AWS Nitro Enclaves (stub with correct structure)

The agent demonstrates the full DSP processing lifecycle:
1. Boot and generate attestation
2. Start a session with the gateway
3. Download documents from MinIO
4. Extract structured data with PII redaction
5. Run result scanning (regex + simulated NER)
6. Submit result with full attestation + end-of-session proof

## Scanner (`reference/scanner/`)

Four scanner types per the spec:

| Scanner | Implementation | Required for |
|---------|---------------|-------------|
| `regex` | Built-in pattern library | All agent types |
| `ner` | Microsoft Presidio wrapper | ml_structured, llm_freeform |
| `statistical` | Benford's law + precision checks | pii-high+ (recommended) |
| `llm_output_filter` | Presidio with low threshold | llm_freeform |

## Sidecar Verifier (`reference/sidecar/`)

Independent process that monitors agent behavior:
- Network I/O (connections, destinations, bytes)
- Memory allocation (RSS, peak usage)
- DNS queries

Compares observations against agent self-reported claims and reports
mismatches as `sidecar.network_mismatch` or `sidecar.anomaly_detected`
audit events.

## Docker Compose Configurations

| File | Purpose | Gateway |
|------|---------|---------|
| `reference/docker-compose.yml` | Full demo with dashboard | Python |
| `reference/docker-compose.gramine.yml` | Gramine SGX overlay | Python |
| `reference/docker-compose.sgx.yml` | Real Intel SGX overlay | Python |
| `reference/sandbox/docker-compose.yml` | Conformance sandbox | Go |
