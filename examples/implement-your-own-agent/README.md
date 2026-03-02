# Build a DSP-Compliant Agent from Scratch

A step-by-step tutorial that takes you from zero to a working DSP agent.
You will write ~200 lines of Python that talk to a real gateway, process
documents inside a (simulated) enclave, redact PII, scan results, and
submit a schema-valid result envelope — the same lifecycle the reference
agent follows, but explained one piece at a time.

## Prerequisites

| Requirement | Why |
|---|---|
| Python 3.11+ | Runtime for the agent |
| `httpx` | HTTP client for gateway API calls |
| Docker + Docker Compose | Run the reference gateway + MinIO stack |
| The DSP repo cloned | `git clone https://github.com/aminueza/dssp-protocol` |

```bash
pip install httpx minio
```

Start the reference gateway so you have something to talk to:

```bash
cd dsp-protocol/reference
docker compose up -d gateway storage setup
```

Wait until `http://localhost:8080/health` returns `{"status":"ok"}`.

---

## The 7-Step Agent Lifecycle

```
┌──────────────────────────────────────────────────────────┐
│                     Document Owner                       │
│  ┌────────┐   ┌──────────┐   ┌────────────────────────┐ │
│  │ Storage │   │ Gateway  │   │ Enclave (your agent)   │ │
│  │ (MinIO) │◄──│ (Go)     │◄──│ Step 1-7 happen here   │ │
│  └────────┘   └──────────┘   └────────────────────────┘ │
└──────────────────────────────────────────────────────────┘
```

1. **Boot & attest** — prove your code is running inside a trusted enclave
2. **Discover** — fetch the contract and manifest from the gateway
3. **Start session** — present your attestation, get a scoped token
4. **Download documents** — use the token to pull files from owner storage
5. **Process & redact** — extract structured data, redact PII per contract
6. **Scan results** — run regex + NER scanners on the output
7. **Submit result** — build the result envelope and POST it

---

## Step 0 — Project Structure

```
my-agent/
├── agent.py           # The agent you will write
├── requirements.txt   # httpx, minio
```

Create `requirements.txt`:

```
httpx>=0.27
minio>=7.2
```

---

## Step 1 — Boot & Generate Attestation

In production, this calls into SGX/SEV-SNP/Nitro hardware. For development,
generate a **simulated** attestation that is structurally identical to a real
one — the gateway accepts `sandbox` enclave types in dev mode.

```python
# agent.py — Step 1: Attestation
import hashlib
import base64
import json
import uuid
from datetime import datetime, timezone


AGENT_ID = "my-first-agent"
AGENT_VERSION = "0.1.0"


def now_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def generate_attestation(nonce: bytes = b"") -> dict:
    """Simulated enclave attestation.

    In production, replace this with your TEE SDK:
      - SGX: read /dev/attestation/quote (via Gramine)
      - SEV-SNP: call /dev/sev-guest
      - Nitro: call /dev/nsm
    """
    measurement = sha256_hex(b"my-agent-enclave-v1")
    agent_hash = {
        "algorithm": "sha-256",
        "value": sha256_hex(f"{AGENT_ID}:{AGENT_VERSION}".encode()),
    }

    report_body = {
        "type": "simulated",
        "measurement": measurement,
        "agent_hash": agent_hash["value"],
        "nonce": sha256_hex(nonce) if nonce else "",
        "timestamp": now_utc(),
    }

    signature = base64.b64encode(
        json.dumps(report_body, sort_keys=True).encode()
    ).decode()

    return {
        "enclave_type": "sandbox",       # real: "sgx", "sev-snp", "nitro"
        "measurement": measurement,
        "agent_hash": agent_hash,
        "timestamp": now_utc(),
        "signed_by": "simulated-ca",     # real: "intel-qe", "amd-ark", etc.
        "signature": signature,
    }
```

**Key rule:** The `measurement` must stay constant across the session. The
gateway compares the start-of-session and end-of-session measurements to
detect tampering.

---

## Step 2 — Discover Contract & Manifest

The gateway exposes manifests (what documents exist) and contracts (what you
are allowed to do). Your agent fetches both:

```python
import httpx

GATEWAY = "http://localhost:8080"
API = f"{GATEWAY}/v0.1"


def discover():
    """Fetch the first available contract and manifest."""
    # List contracts
    r = httpx.get(f"{API}/contracts", timeout=10)
    r.raise_for_status()
    contracts = r.json()["items"]
    assert contracts, "No contracts found — did you run the setup container?"
    contract = contracts[0]

    # List manifests
    r = httpx.get(f"{API}/manifests", timeout=10)
    r.raise_for_status()
    manifests = r.json()["items"]
    assert manifests, "No manifests found"
    manifest = manifests[0]

    print(f"Contract: {contract['contract_id']}")
    print(f"  Operations allowed: {contract['permissions']['operations']}")
    print(f"Manifest: {manifest['manifest_id']}")
    print(f"  Documents: {len(manifest.get('documents', []))}")

    return contract, manifest
```

**What to check in the contract before proceeding:**

| Field | Check |
|---|---|
| `status` | Must be `"active"` |
| `permissions.valid_from` / `valid_until` | Current time must be inside window |
| `permissions.operations` | Only do what's listed here |
| `restrictions.result_policy.pii_redaction_rules` | Map of PII field → redaction method |
| `attestation_requirements.enclave_types` | Your enclave must be in this list |

---

## Step 3 — Start a Processing Session

POST to `/v0.1/sessions` with your attestation. The gateway validates the
attestation, checks the contract, and returns a scoped token + the full
manifest:

```python
def start_session(contract: dict, manifest: dict, attestation: dict) -> dict:
    """Start a processing session. Returns session_id + scoped token."""
    session_req = {
        "contract_id": contract["contract_id"],
        "manifest_id": manifest["manifest_id"],
        "attestation": {
            "enclave_type": attestation["enclave_type"],
            "measurement": attestation["measurement"],
            "agent_hash": attestation["agent_hash"],
            "timestamp": attestation["timestamp"],
            "signature": attestation["signature"],
        },
        "agent_org_id": contract["consumer"]["org_id"],
        "agent_id": AGENT_ID,
    }

    r = httpx.post(f"{API}/sessions", json=session_req, timeout=10)

    if r.status_code == 403:
        # Contract violation — the gateway tells you exactly what failed
        violations = r.json().get("violations", [])
        for v in violations:
            print(f"  VIOLATION: [{v['severity']}] {v['rule']}: {v['description']}")
        raise SystemExit("Session rejected — fix violations above")

    r.raise_for_status()
    session = r.json()

    print(f"Session started: {session['session_id']}")
    print(f"  Token expires: {session['token']['expires_at']}")
    print(f"  Documents accessible: {len(session['token']['scope']['document_ids'])}")

    return session
```

**The response gives you:**

```json
{
  "session_id": "ps-a1b2c3d4e5f67890",
  "token": {
    "token": "dsp-tok-...",
    "expires_at": "2026-03-02T15:00:00Z",
    "scope": {
      "document_ids": ["doc-f47ac10b58cc4372", "doc-g58bd21c69dd5483"],
      "operations": ["extract_text", "extract_tables"]
    }
  },
  "manifest": { "...full manifest..." },
  "expires_at": "2026-03-02T15:00:00Z"
}
```

---

## Step 4 — Download Documents

Use the scoped token to pull documents from owner storage. In the reference
stack, storage is MinIO:

```python
from minio import Minio


def download_documents(manifest: dict) -> list[tuple[dict, bytes]]:
    """Download all documents listed in the manifest."""
    client = Minio(
        "localhost:9100",  # docker-compose maps container:9000 → host:9100
        access_key="dsp-owner",
        secret_key="dsp-owner-secret-key",
        secure=False,
    )

    documents = []
    for doc in manifest.get("documents", []):
        ref = doc["storage_ref"]
        print(f"  Downloading {ref['key']} from {ref['bucket']}")

        response = client.get_object(ref["bucket"], ref["key"])
        content = response.read()
        response.close()
        response.release_conn()

        # Verify hash matches manifest declaration
        actual_hash = sha256_hex(content)
        declared_hash = doc.get("hash", {}).get("value", "")
        if declared_hash and actual_hash != declared_hash:
            print(f"  WARNING: hash mismatch for {doc['document_id']}")

        documents.append((doc, content))

    return documents
```

**Critical:** always verify the document hash against the manifest. This
proves you processed the exact bytes the owner declared, and goes into your
attestation claims.

---

## Step 5 — Process Documents & Redact PII

This is where your actual business logic lives. The example below extracts
fields from a bank statement and redacts PII according to the contract rules.

```python
def redact(value: str, method: str) -> str:
    """Apply a DSP redaction method to a PII value.

    DSP defines these methods (see spec §3.4):
      mask_last_4   →  ****4372
      hash_sha256   →  SHA256:a1b2c3d4...
      suppress      →  [REDACTED]
      generalize    →  J. D.
      allow         →  (pass through unchanged)
    """
    if method == "allow":
        return value
    if method == "mask_last_4":
        return "*" * max(0, len(value) - 4) + value[-4:] if len(value) > 4 else "****"
    if method == "hash_sha256":
        return "SHA256:" + sha256_hex(value.encode())[:16]
    if method == "suppress":
        return "[REDACTED]"
    if method == "generalize":
        return " ".join(p[0] + "." for p in value.split() if p)
    return value


def process_document(doc_meta: dict, content: bytes, contract: dict) -> dict:
    """Extract structured data and redact PII per contract rules."""
    text = content.decode("utf-8")

    # --- Your extraction logic here ---
    # Parse the document, extract fields and tables.
    # This is a simplified example for bank statements:
    fields = {}
    import re
    for key, pattern in {
        "account_holder": r"Account Holder:\s*(.+)",
        "account_number": r"Account Number:\s*(.+)",
        "currency": r"Currency:\s*(\w+)",
        "opening_balance": r"Opening Balance:\s*([\d.]+)",
        "closing_balance": r"Closing Balance:\s*([\d.]+)",
    }.items():
        m = re.search(pattern, text)
        if m:
            fields[key] = m.group(1).strip()

    # --- Apply PII redaction from contract rules ---
    redaction_rules = (
        contract
        .get("restrictions", {})
        .get("result_policy", {})
        .get("pii_redaction_rules")
    ) or {}  # may be null — default to empty (suppress all PII)

    pii_encountered = []
    pii_redacted = []
    PII_FIELDS = {"account_holder", "account_number", "iban", "routing_number"}

    for field_name in list(fields.keys()):
        if field_name in PII_FIELDS:
            pii_encountered.append(field_name)
            method = redaction_rules.get(field_name, "suppress")
            fields[field_name] = redact(fields[field_name], method)
            pii_redacted.append(field_name)

    return {
        "source_document_id": doc_meta["document_id"],
        "source_document_hash": doc_meta.get("hash", {}),
        "extraction_type": "financial/bank-statement",
        "confidence": 0.95,
        "fields": fields,
        "pii_encountered": pii_encountered,
        "pii_redacted": pii_redacted,
    }
```

**Compliance rules that will bite you:**

1. **Never include raw document content** in the result — only structured
   extractions.
2. **Redact every PII field** the contract lists, using the exact method
   specified. `suppress` means `[REDACTED]`, not an empty string.
3. **Transaction descriptions are pii_bearing** — they often contain
   counterparty names. You must NER-scan them.

---

## Step 6 — Scan Results for Residual PII

Before the result leaves the enclave boundary, it **must** pass through
result scanners. The contract specifies which scanners are required
(`restrictions.result_scanning.required_scanners`).

```python
PII_PATTERNS = {
    "iban": r"\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7,25}\b",
    "account_number": r"\b\d{10,20}\b",
    "person_name": r"\b[A-Z][a-z]+ [A-Z][a-z]+\b",
    "email": r"\b[\w.-]+@[\w.-]+\.\w+\b",
}


def scan_result(extractions: list[dict]) -> dict:
    """Scan the result for residual PII that slipped past redaction.

    In production, run multiple scanners:
      - regex patterns (fast, catches known formats)
      - NER model (catches names/orgs the regex misses)
      - statistical scanner (flags suspiciously high-entropy fields)
    """
    import re

    result_text = json.dumps(extractions)
    verdicts = []

    # Regex scanner
    regex_findings = 0
    for pii_type, pattern in PII_PATTERNS.items():
        matches = re.findall(pattern, result_text)
        regex_findings += len(matches)

    verdicts.append({
        "scanner_type": "regex_pattern",
        "scanner_version": "1.0.0",
        "verdict": "pass" if regex_findings == 0 else "flag",
        "findings_count": regex_findings,
        "details": f"Checked {len(PII_PATTERNS)} patterns",
    })

    # NER scanner (stub — in production use spaCy or a transformer model)
    ner_findings = 0
    for ext in extractions:
        for _key, val in ext.get("fields", {}).items():
            if isinstance(val, str) and re.search(r"[A-Z][a-z]+ [A-Z][a-z]+", val):
                ner_findings += 1

    verdicts.append({
        "scanner_type": "ner_entity",
        "scanner_version": "1.0.0-stub",
        "verdict": "pass" if ner_findings == 0 else "flag",
        "findings_count": ner_findings,
        "details": "NER scan (stub implementation)",
    })

    overall = all(v["verdict"] == "pass" for v in verdicts)
    return {
        "performed": True,
        "verdicts": verdicts,
        "overall_passed": overall,
        "fields_modified_by_scan": 0,
        "scan_duration_ms": 120,
    }
```

**If `scan_failure_action` in the contract is `"block_result"`**, and any
scanner returns `"flag"`, you **must not** submit the result. Redact the
flagged fields and re-scan, or abort.

---

## Step 7 — Build & Submit the Result Envelope

The result envelope is the **only artifact that leaves the enclave**. It must
conform to `result.schema.json`:

```python
def build_result_envelope(
    session_id: str,
    contract_id: str,
    extractions: list[dict],
    pii_report: dict,
    scan_report: dict,
    attestation: dict,
    input_hashes: list[dict],
) -> dict:
    """Build a schema-compliant DSP result envelope."""

    # Attestation claims prove what happened inside the enclave
    attestation["claims"] = {
        "documents_processed": len(extractions),
        "processing_duration_ms": 3500,
        "input_document_hashes": input_hashes,
        "network_destinations": ["gateway:8080"],
        "output_result_hash": {
            "algorithm": "sha-256",
            "value": sha256_hex(
                json.dumps(extractions, sort_keys=True).encode()
            ),
        },
    }

    return {
        "$schema": "https://dsp.dev/schema/result/v0.1",
        "dsp_version": "0.1",
        "result_id": f"rs-{uuid.uuid4().hex[:16]}",
        "contract_id": contract_id,
        "session_id": session_id,
        "produced_at": now_utc(),
        "attestation": attestation,
        "extractions": [
            {
                "source_document_id": e["source_document_id"],
                "source_document_hash": e["source_document_hash"],
                "extraction_type": e["extraction_type"],
                "confidence": e["confidence"],
                "fields": e["fields"],
            }
            for e in extractions
        ],
        "pii_report": pii_report,
        "result_scan": scan_report,
    }


def submit_result(session_id: str, envelope: dict) -> dict:
    """POST the result envelope to the gateway."""
    r = httpx.post(
        f"{API}/sessions/{session_id}/result",
        json=envelope,
        timeout=30,
    )

    if r.status_code not in (200, 201):
        print(f"Result rejected ({r.status_code}): {r.text}")
        raise SystemExit(1)

    response = r.json()
    validation = response.get("validation", {})

    if validation.get("valid"):
        print("Result accepted and validated")
    else:
        print("Result accepted with issues:")
        for issue in validation.get("issues", []):
            print(f"  - {issue}")

    return response
```

---

## Putting It All Together

```python
def main():
    print("=== My DSP Agent ===\n")

    # Step 1: Generate attestation
    print("[1/7] Generating attestation...")
    attestation = generate_attestation()

    # Step 2: Discover contract + manifest
    print("[2/7] Discovering contract and manifest...")
    contract, manifest = discover()

    # Step 3: Start session
    print("[3/7] Starting session...")
    session = start_session(contract, manifest, attestation)
    session_id = session["session_id"]
    manifest_data = session.get("manifest", manifest)

    # Step 4: Download documents
    print("[4/7] Downloading documents...")
    documents = download_documents(manifest_data)

    # Step 5: Process and redact
    print("[5/7] Processing documents...")
    extractions = []
    all_pii_encountered = set()
    all_pii_redacted = set()
    input_hashes = []

    for doc_meta, content in documents:
        result = process_document(doc_meta, content, contract)
        extractions.append(result)
        all_pii_encountered.update(result["pii_encountered"])
        all_pii_redacted.update(result["pii_redacted"])
        input_hashes.append({
            "algorithm": "sha-256",
            "value": sha256_hex(content),
        })

    # Step 6: Scan results
    print("[6/7] Scanning results for residual PII...")
    scan_report = scan_result(extractions)
    for v in scan_report["verdicts"]:
        status = "PASS" if v["verdict"] == "pass" else "FLAG"
        print(f"  {status}: {v['scanner_type']} ({v['findings_count']} findings)")

    # Step 7: Build and submit
    print("[7/7] Submitting result...")
    pii_report = {
        "fields_encountered": sorted(all_pii_encountered),
        "fields_redacted": sorted(all_pii_redacted),
        "raw_content_included": False,
        "compliance_status": "compliant",
    }

    envelope = build_result_envelope(
        session_id=session_id,
        contract_id=contract["contract_id"],
        extractions=extractions,
        pii_report=pii_report,
        scan_report=scan_report,
        attestation=attestation,
        input_hashes=input_hashes,
    )

    submit_result(session_id, envelope)
    print("\nDone.")


if __name__ == "__main__":
    main()
```

Run it:

```bash
python agent.py
```

---

## Common Pitfalls & How to Fix Them

| Symptom | Cause | Fix |
|---|---|---|
| `403 contract_violation` on session start | Attestation `enclave_type` not in contract's `enclave_types` list | Use a type the contract allows, or use `"sandbox"` in dev |
| `400 missing_field` on result submit | Required schema fields missing | Check `result.schema.json` — `pii_report`, `result_scan`, `attestation.claims` are all required |
| Gateway rejects result as "PII leak detected" | Your result contains raw text or un-redacted PII | Apply redaction rules from `contract.restrictions.result_policy.pii_redaction_rules` to every field |
| Audit event shows `measurement_mismatch` | End-of-session attestation measurement differs from start | In production, this means the enclave was modified — in dev, keep the same measurement value |
| `extraction_type` validation fails | Used free text instead of a known classification | Use values from the `DocumentClassification` enum in `common.schema.json` |

---

## Validating Your Output Locally

Use the reference validator before submitting:

```bash
cd dsp-protocol/reference/validator

# Validate your result envelope
python validate.py --schema ../../schemas/result.schema.json your-result.json

# Validate with full audit chain check
python validate.py --check-chain ../../schemas/result.schema.json your-result.json
```

---

## Going to Production

| Dev / Tutorial | Production |
|---|---|
| `enclave_type: "sandbox"` | `"sgx"`, `"sev-snp"`, `"tdx"`, or `"nitro"` |
| Simulated attestation | Real hardware attestation via TEE SDK |
| MinIO on localhost | Owner's S3/Azure Blob/GCS with scoped SAS tokens |
| `httpx` to gateway on `:8080` | mTLS to gateway on `:443` |
| Regex PII scanner | spaCy/transformer NER + regex + statistical |
| Self-signed signatures | PKI signatures verifiable via attestation CA chain |

The protocol is the same — only the attestation backend and network
transport change. Your extraction logic, redaction pipeline, and result
envelope structure stay identical.

---

## Further Reading

- **Spec**: `spec/dsp-v0.1.md` — full protocol specification
- **API**: `spec/dsp-api-v0.1.yaml` — OpenAPI 3.1 definition (load in Swagger UI)
- **Schemas**: `schemas/*.schema.json` — JSON Schema for every DSP artifact
- **Reference agent**: `reference/agent/main.py` — production-grade example
- **Attestation backends**: `reference/agent/attestation.py` — SGX, Nitro, simulated
- **Example files**: `examples/bank-statement-extraction/` — complete manifest, contract, and result

