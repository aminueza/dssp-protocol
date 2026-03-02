# DSP Gateway -- Reference Implementation (Go)

A runnable Go server implementing the Document Sovereignty Protocol (DSP) v0.1 wire protocol.

**This is a reference implementation for development and testing.** Attestation verification is simulated. Production deployments must use real hardware attestation (SGX, SEV-SNP, TDX, Nitro).

## Quick start

```bash
# Run directly
go run .

# Or build and run
go build -o dsp-gateway .
./dsp-gateway

# With Docker
docker build -t dsp-gateway .
docker run -p 8080:8080 dsp-gateway
```

## Configuration

Environment variables:

| Variable             | Default  | Description                    |
|----------------------|----------|--------------------------------|
| `DSP_PORT`           | `8080`   | HTTP listen port               |
| `DSP_STORAGE_ADAPTER`| `memory` | Storage backend (memory only)  |
| `DSP_LOG_LEVEL`      | `info`   | Log level (debug/info/warn/error) |

## Endpoints

| Method | Path                                     | Description              |
|--------|------------------------------------------|--------------------------|
| POST   | `/v0.1/manifests`                        | Register a manifest      |
| GET    | `/v0.1/manifests/{id}`                   | Get manifest by ID       |
| GET    | `/v0.1/manifests`                        | List manifests           |
| POST   | `/v0.1/contracts`                        | Create a contract        |
| GET    | `/v0.1/contracts/{id}`                   | Get contract by ID       |
| PATCH  | `/v0.1/contracts/{id}`                   | Update contract status   |
| GET    | `/v0.1/contracts`                        | List contracts           |
| POST   | `/v0.1/sessions`                         | Start a processing session |
| GET    | `/v0.1/sessions/{id}`                    | Get session by ID        |
| POST   | `/v0.1/sessions/{id}/heartbeat`          | Send heartbeat           |
| POST   | `/v0.1/sessions/{id}/complete`           | Complete a session       |
| GET    | `/v0.1/sessions/{id}/result`             | Get session result       |
| POST   | `/v0.1/audit/events`                     | Append audit event       |
| GET    | `/v0.1/audit/events`                     | List audit events        |
| POST   | `/v0.1/storage/grant-access`             | Grant scoped access      |
| GET    | `/v0.1/.well-known/dsp-configuration`    | DSP configuration        |
| GET    | `/health`                                | Health check             |

## Protocol flow example

```bash
# 1. Register a manifest
curl -X POST http://localhost:8080/v0.1/manifests \
  -H 'Content-Type: application/json' \
  -d '{
    "owner": {"org_id": "org-acme-bank"},
    "documents": [
      {
        "document_id": "doc-abc123def456",
        "classification": "financial/bank-statement",
        "sensitivity": "pii-high",
        "format": "application/pdf",
        "hash": {"algorithm": "sha-256", "value": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"}
      }
    ]
  }'

# 2. Create a contract
curl -X POST http://localhost:8080/v0.1/contracts \
  -H 'Content-Type: application/json' \
  -d '{
    "owner": {"org_id": "org-acme-bank"},
    "consumer": {"org_id": "org-audit-firm", "agent_type": "ml_structured"},
    "permissions": {
      "operations": ["extract_tables", "extract_key_value"],
      "max_session_duration_seconds": 1800
    },
    "restrictions": {
      "network_policy": {"egress": "deny_all"},
      "storage_policy": "memory_only",
      "result_policy": {
        "pii_redaction_rules": {
          "account_number": "mask_last_4",
          "account_holder_name": "hash_sha256",
          "balance": "allow"
        }
      },
      "result_scanning": {"enabled": true, "required_scanners": ["regex", "ner"]}
    },
    "attestation_requirements": {
      "enclave_types": ["sgx", "sev-snp", "sandbox"],
      "must_include": ["agent_binary_hash", "output_result_hash"]
    }
  }'

# 3. Start a session (use manifest_id and contract_id from above)
curl -X POST http://localhost:8080/v0.1/sessions \
  -H 'Content-Type: application/json' \
  -d '{
    "contract_id": "<contract_id>",
    "manifest_id": "<manifest_id>",
    "attestation": {"enclave_type": "sandbox"},
    "agent_org_id": "org-audit-firm"
  }'

# 4. Send heartbeat
curl -X POST http://localhost:8080/v0.1/sessions/<session_id>/heartbeat \
  -H 'Content-Type: application/json' \
  -d '{}'

# 5. Complete session
curl -X POST http://localhost:8080/v0.1/sessions/<session_id>/complete \
  -H 'Content-Type: application/json' \
  -d '{"status": "completed"}'

# 6. View audit events
curl http://localhost:8080/v0.1/audit/events

# 7. Check DSP configuration
curl http://localhost:8080/v0.1/.well-known/dsp-configuration
```

## Architecture

```
main.go                          Entry point, HTTP server, middleware
internal/
  types/types.go                 Core DSP types matching JSON schemas
  store/store.go                 Store interface + in-memory implementation
  handler/handler.go             HTTP handlers for all endpoints
  handler/contract_enforcement.go Contract rule enforcement
  audit/chain.go                 Merkle-chained audit ledger
  canonical/json.go              RFC 8785 JSON canonicalization
```

## Key features

- **Contract enforcement**: session limits, expiry checks, enclave type validation, agent hash verification
- **Result validation**: PII compliance, network policy, scan verdict checking, numeric precision enforcement, sub-agent chain validation
- **Merkle audit chain**: SHA-256 hashed, append-only event ledger with chain integrity verification
- **RFC 8785 canonical JSON**: deterministic serialization for hash computation
- **Privacy budget tracking**: epsilon-based budget enforcement across sessions
- **Thread-safe**: all state protected by sync.RWMutex
- **Zero external dependencies**: uses only the Go standard library and google/uuid

## License

Apache 2.0
