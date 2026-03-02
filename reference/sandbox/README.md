# DSSP Sandbox — Docker Compose Demo

A complete, runnable demo of the Document Sovereignty Protocol & Privacy.

## Quick Start

```bash
docker compose up --build
```

Then visit:
- **Gateway API**: http://localhost:8080/v0.1/.well-known/dssp-configuration
- **Audit Viewer**: http://localhost:8082
- **MinIO Console**: http://localhost:9001 (login: minioadmin/minioadmin)

## What Happens

1. **MinIO** starts as the document storage backend
2. **minio-setup** creates the `dssp-documents` bucket and uploads sample PDFs
3. **Gateway** starts the DSSP API server connected to MinIO
4. **Scanner** starts the regex PII scanner service
5. **Agent Demo** runs a complete processing lifecycle:
   - Creates a manifest (document discovery)
   - Creates a contract (processing policy with PII redaction rules)
   - Starts a session (within contract limits)
   - Processes documents (simulated extraction with PII redaction)
   - Submits the result (with attestation)
6. **Audit Viewer** shows the event trail with Merkle chain visualization

## Architecture

```
┌─────────────┐     ┌──────────┐     ┌─────────┐
│ Agent Demo  │────►│ Gateway  │────►│  MinIO   │
└─────────────┘     │ (DSP API)│     │(Storage) │
                    └────┬─────┘     └──────────┘
                         │
                    ┌────┴─────┐
                    │ Scanner  │
                    │ (PII)    │
                    └──────────┘
                         │
                    ┌────┴──────┐
                    │  Audit    │
                    │  Viewer   │
                    └───────────┘
```

## Services

| Service | Port | Description |
|---------|------|-------------|
| gateway | 8080 | DSP API server |
| minio | 9000/9001 | S3-compatible storage |
| scanner | 8081 | PII result scanner |
| agent-demo | — | Demo processing agent |
| audit-viewer | 8082 | Audit trail web viewer |

## Customization

Place your own PDF files in `sample-data/` before running `docker compose up`.
They will be automatically uploaded to MinIO.
