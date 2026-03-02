# DSSP Agent Guide

This document is the canonical reference for building, testing, and deploying
DSSP-compliant processing agents. It unifies information from the protocol
specification, JSON schemas, and reference implementation into a single
developer-facing guide.

For the formal specification, see [`spec/dssp-v0.1.md`](spec/dssp-v0.1.md).
For the wire protocol, see [`spec/dssp-api-v0.1.yaml`](spec/dssp-api-v0.1.yaml).

---

## Table of Contents

1. [What Is a DSSP Agent?](#1-what-is-a-dssp-agent)
2. [Agent Types](#2-agent-types)
3. [Agent Lifecycle](#3-agent-lifecycle)
4. [Attestation Backends](#4-attestation-backends)
5. [PII Redaction and Result Scanning](#5-pii-redaction-and-result-scanning)
6. [Sub-Agent Chains](#6-sub-agent-chains)
7. [Contract Compliance Checklist](#7-contract-compliance-checklist)
8. [Security Invariants](#8-security-invariants)
9. [Testing Your Agent](#9-testing-your-agent)
10. [Common Pitfalls](#10-common-pitfalls)
11. [Going to Production](#11-going-to-production)

---

## 1. What Is a DSSP Agent?

A DSSP agent is an untrusted program that processes sensitive documents on
behalf of a consumer organization (auditor, processor, analytics provider).
The key distinction from a traditional API client:

- **The agent runs on the document owner's infrastructure**, not the
  consumer's. Documents never leave the owner's network boundary.
- **The agent runs inside a hardware enclave** (SGX, SEV-SNP, Nitro) that
  isolates it from the host OS. Even a compromised host cannot read document
  contents.
- **The agent must prove what code it runs** via hardware attestation. The
  owner verifies the agent's identity before granting access.
- **Results are inspected before release.** The agent's output passes through
  independent PII scanners before exiting the enclave boundary.

```
┌─────────────────────────────────────────────────────────────┐
│                     Document Owner Infrastructure           │
│                                                             │
│  ┌──────────┐    ┌───────────┐    ┌───────────────────────┐ │
│  │ Storage  │    │  Gateway  │    │ Hardware Enclave      │ │
│  │ (MinIO/  │◄───│  (Go)     │◄───│                       │ │
│  │  S3)     │    │           │    │  ┌─────────────────┐  │ │
│  └──────────┘    └───────────┘    │  │  Agent (yours)  │  │ │
│                       │           │  └────────┬────────┘  │ │
│                       │           │           │           │ │
│                  ┌────┴────┐      │  ┌────────▼────────┐  │ │
│                  │  Audit  │      │  │  PII Scanners   │  │ │
│                  │  Ledger │      │  └────────┬────────┘  │ │
│                  └─────────┘      │           │           │ │
│                                   │  ┌────────▼────────┐  │ │
│                                   │  │ Sidecar Monitor │  │ │
│                                   │  └─────────────────┘  │ │
│                                   └───────────────────────┘ │
│                                                             │
│  Result exits enclave ONLY after scanning ──────────────►   │
└─────────────────────────────────────────────────────────────┘
```

**Trust model:** The owner trusts the *protocol*, not the agent. The
contract, attestation, scanners, sidecar, and audit ledger collectively
ensure the agent can only do what the owner permits.

---

## 2. Agent Types

Every agent must declare its processing model. The type determines which
scanners, privacy controls, and attestation claims are required.

### Decision Tree

```
Is the agent rule-based (regex/template)?
  ├─ YES → agent_type: "deterministic"
  │         Minimum scanning: regex
  │         Privacy budget: RECOMMENDED
  │
  └─ NO → Does the agent produce free-text output?
            ├─ NO → agent_type: "ml_structured"
            │        Minimum scanning: regex + ner
            │        Privacy budget: RECOMMENDED for pii-high
            │
            └─ YES → agent_type: "llm_freeform"
                      Minimum scanning: regex + ner + llm_output_filter
                      Privacy budget: REQUIRED
                      Document sanitization: RECOMMENDED
                      Result scanning: REQUIRED
```

### Comparison Matrix

| | `deterministic` | `ml_structured` | `llm_freeform` |
|---|---|---|---|
| **Examples** | Regex parser, template matcher | LayoutLM, NER model, table extractor | GPT-4, Claude, Llama |
| **Output** | Typed fields/tables only | Typed fields/tables only | May produce free text |
| **Required scanners** | `regex` | `regex` + `ner` | `regex` + `ner` + `llm_output_filter` |
| **Privacy budget** | Recommended | Recommended for pii-high | **Required** |
| **Document sanitization** | Optional | Optional | **Recommended** |
| **Result scanning** | Recommended | Recommended | **Required** |
| **Risk profile** | Low | Medium | High |

### LLM-Specific Risks

Agents classified as `llm_freeform` face additional risks that the protocol
explicitly addresses:

- **Training data memorization** — LLMs may reproduce PII from their training
  data in generated text, even when the input document doesn't contain it.
- **Embedded PII in free text** — Descriptions, summaries, and other free-text
  fields may contain PII that regex patterns cannot catch.
- **Non-determinism** — The same input can produce different outputs across
  runs, making static testing insufficient. Runtime scanning is essential.
- **Prompt injection** — Malicious content in documents can manipulate LLM
  behavior. Document sanitization strips hidden text, zero-width characters,
  and known injection patterns before the agent sees the content.

---

## 3. Agent Lifecycle

Every DSSP agent follows the same 7-step lifecycle, regardless of agent type
or attestation backend.

```
Step 1         Step 2          Step 3          Step 4
Boot &    ───► Discover   ───► Start     ───► Download
Attest         Contract +      Session         Documents
               Manifest
                                │
                                ▼
Step 7         Step 6          Step 5
Submit    ◄─── Scan       ◄─── Process &
Result         Results         Redact PII
```

### Step 1 — Boot and Generate Attestation

The agent generates a hardware attestation report proving its identity
(code hash, enclave type, measurement). In production, this calls into
SGX/SEV-SNP/Nitro hardware. In development, use the simulated backend.

```python
from attestation import create_attestor

attestor = create_attestor(agent_id="my-agent", agent_version="1.0.0")
report = attestor.generate_report(user_data=b"nonce")
```

**Key rule:** The `measurement` value must remain constant across the entire
session. The gateway compares start and end-of-session measurements to detect
enclave tampering.

### Step 2 — Discover Contract and Manifest

Fetch the processing contract (what you're allowed to do) and the document
manifest (what documents exist) from the gateway:

```
GET /v0.1/contracts → list of contracts
GET /v0.1/manifests → list of manifests
```

**Before proceeding, verify:**

| Field | Check |
|---|---|
| `contract.status` | Must be `"active"` |
| `permissions.valid_from` / `valid_until` | Current time must be inside the window |
| `permissions.operations` | Only perform operations listed here |
| `attestation_requirements.enclave_types` | Your enclave type must be in this list |
| `restrictions.result_policy.pii_redaction_rules` | Map of PII field to redaction method |

### Step 3 — Start a Processing Session

POST your attestation to the gateway. It validates the attestation against
the contract and returns a scoped token:

```
POST /v0.1/sessions
{
  "contract_id": "...",
  "manifest_id": "...",
  "attestation": { ... },
  "agent_org_id": "...",
  "agent_id": "..."
}
```

The response contains:
- `session_id` — identifies this processing session
- `token` — scoped access token with `expires_at`, permitted `document_ids`,
  and allowed `operations`
- `manifest` — the full manifest with document metadata and storage references

### Step 4 — Download Documents from Owner Storage

Use the scoped token to pull documents from the owner's storage (MinIO, S3,
GCS, Azure Blob). Always verify the document hash against the manifest
declaration — this proves you processed the exact bytes the owner declared.

```python
actual_hash = sha256(content)
declared_hash = doc["hash"]["value"]
assert actual_hash == declared_hash, "Document hash mismatch"
```

### Step 5 — Process and Redact PII

Extract structured data from documents and redact PII according to the
contract's `pii_redaction_rules`. DSSP defines these redaction methods:

| Method | Output | Example |
|---|---|---|
| `mask_last_4` | `****4372` | Account numbers |
| `hash_sha256` | `SHA256:a1b2c3d4...` | IBANs, routing numbers |
| `suppress` | `[REDACTED]` | Names, addresses |
| `generalize` | `J. D.` | Person names (initials) |
| `allow` | Original value | Non-PII fields |

Apply the **exact** method specified in the contract for each PII field.
Using a different method is a contract violation.

### Step 6 — Scan Results for Residual PII

Before the result exits the enclave, it must pass through independent
scanners. The contract specifies which scanners are required via
`restrictions.result_scanning.required_scanners`.

| Scanner | What it catches | When required |
|---|---|---|
| `regex` | Known PII formats (IBANs, SSNs, credit cards, emails) | All agent types |
| `ner` | Person names, organizations, locations | `ml_structured`, `llm_freeform` |
| `llm_output_filter` | PII in LLM-generated free text | `llm_freeform` |
| `statistical` | Re-identification risk, Benford's law anomalies | Recommended for pii-high+ |

If any scanner returns `"flag"`, the result must be handled according to
`scan_failure_action`:

| Action | Behavior |
|---|---|
| `block_result` (default) | Do **not** submit the result. Redact flagged fields and re-scan, or abort. |
| `flag_and_deliver` | Submit with flags attached. The owner decides. |
| `quarantine` | Submit to a quarantine store for manual review. |

### Step 7 — Build and Submit the Result Envelope

The result envelope is the **only artifact that exits the enclave**. It must
conform to [`schemas/result.schema.json`](schemas/result.schema.json):

```
POST /v0.1/sessions/{session_id}/result
{
  "$schema": "https://dssp.dev/schema/result/v0.1",
  "dssp_version": "0.1",
  "result_id": "rs-...",
  "contract_id": "...",
  "session_id": "...",
  "produced_at": "...",
  "attestation": { ... with claims ... },
  "extractions": [ ... ],
  "pii_report": { ... },
  "result_scan": { ... },
  "end_of_session_attestation": { ... }
}
```

The `attestation.claims` section proves what happened inside the enclave:

```json
{
  "input_document_hashes": [ ... ],
  "network_destinations": ["storage:9000", "gateway:8080"],
  "output_result_hash": { "algorithm": "sha-256", "value": "..." },
  "sub_agent_chain": [ ... ]
}
```

---

## 4. Attestation Backends

DSSP supports multiple hardware attestation backends via a pluggable
interface. The reference implementation provides three backends in
[`reference/agent/attestation.py`](reference/agent/attestation.py).

### Backend Comparison

| Backend | `enclave_type` | Hardware | Measurement source | When to use |
|---|---|---|---|---|
| **Simulated** | `sandbox` | None | Self-signed hash | Dev, CI, learning |
| **Gramine-direct** | `sgx-simulated` | None | Gramine manifest hash | Testing SGX quote format |
| **Gramine-SGX** | `sgx` | Intel SGX CPU | CPU-measured MRENCLAVE | Production (Intel) |
| **Nitro** | `nitro` | EC2 Nitro instance | EIF image hash | Production (AWS) |

### Selecting a Backend

Set the `ENCLAVE_MODE` environment variable:

```bash
# Development
ENCLAVE_MODE=simulated    # Default — no hardware needed

# Testing SGX format
ENCLAVE_MODE=gramine      # Auto-detects gramine-direct vs gramine-sgx

# Production
ENCLAVE_MODE=nitro        # Requires EC2 Nitro instance
```

Auto-detection order (when `ENCLAVE_MODE` is unset):

1. `/dev/attestation/quote` exists → `gramine`
2. `/dev/nsm` exists → `nitro`
3. Fallback → `simulated`

### Attestation Interface

All backends implement the same interface:

```python
class Attestor(ABC):
    def get_measurement(self) -> str: ...
    def generate_report(self, user_data: bytes = b"") -> AttestationReport: ...
    def end_of_session_report(self, start_measurement: str) -> dict: ...
    def get_enclave_type(self) -> str: ...
    def get_backend_name(self) -> str: ...
```

The `AttestationReport` dataclass contains:

| Field | Purpose |
|---|---|
| `enclave_type` | `"sandbox"`, `"sgx"`, `"sev-snp"`, `"nitro"` |
| `measurement` | MRENCLAVE (SGX), launch digest (Nitro), etc. |
| `agent_hash` | `{"algorithm": "sha-256", "value": "..."}` |
| `timestamp` | ISO-8601 time of attestation |
| `signed_by` | CA identity (`"intel-qe"`, `"aws-nitro-nsm"`, `"simulated-ca"`) |
| `signature` | Base64 signature over the report |
| `raw_quote` | Base64 raw hardware quote (SGX DCAP, Nitro NSM document) |
| `platform_certificate_chain` | Certificate chain for verification |

### Contract Attestation Requirements

The contract specifies which enclave types and attestation claims are
acceptable:

```json
{
  "attestation_requirements": {
    "enclave_types": ["sgx", "sev-snp", "nitro"],
    "require_measurement": true,
    "must_include": [
      "result_scan_verdict",
      "end_of_session_measurement",
      "sub_agent_chain_declaration"
    ]
  }
}
```

If your enclave type is not in `enclave_types`, the gateway will reject the
session with a `403 contract_violation`.

---

## 5. PII Redaction and Result Scanning

### Redaction Pipeline

PII handling happens in two stages:

```
Stage 1: Agent Redaction          Stage 2: Independent Scanning
┌─────────────────────┐           ┌─────────────────────────┐
│ Agent extracts data  │           │ Scanner inspects output  │
│ and applies contract │──────────►│ for residual PII that    │
│ redaction rules      │           │ slipped past redaction   │
└─────────────────────┘           └─────────────────────────┘
```

**Stage 1** is the agent's responsibility. Apply the exact redaction method
from `contract.restrictions.result_policy.pii_redaction_rules` to every PII
field.

**Stage 2** is a separate, independent process. The scanner binary runs
inside the enclave but is not part of the agent. It catches PII that the
agent missed.

### PII-Bearing Columns

Table columns can contain embedded PII in free text even when the column
itself is not a dedicated PII field. Common examples:

- Transaction `description` columns (contain counterparty names, addresses)
- `memo` and `notes` fields
- `reference` columns with free-text references

Columns must declare `pii_bearing: true` when they may contain embedded PII.
Values in `pii_bearing` columns must be NER-scanned before leaving the
enclave.

### Privacy Budget

The privacy budget prevents re-identification attacks where an adversary
combines results from multiple sessions to identify individuals.

| Control | Purpose |
|---|---|
| `epsilon` / `delta` | Differential privacy budget. Limits total information extractable. |
| `k_anonymity_min` | Result fields must be indistinguishable from k-1 others. |
| `max_unique_values_per_field` | Prevents exact figures from being unique identifiers. |
| `aggregation_minimum_records` | No field from fewer than N source documents. |
| `budget_window` | Time window: `per_session`, `per_day`, `per_contract`, `lifetime`. |

The gateway tracks budget consumption across sessions and rejects requests
that would exceed the budget.

### Numeric Precision Controls

An adversarial agent can encode information in trailing digits of numeric
fields (steganographic exfiltration). The contract's
`result_policy.numeric_precision_policy` controls this:

| Control | Purpose |
|---|---|
| `max_decimal_places` | Maximum decimals for currency fields (default: 2) |
| `max_significant_digits` | Maximum significant digits for any numeric field |
| `enforce_standard_rounding` | Require IEEE 754 round-half-to-even |
| `detect_entropy_anomaly` | Scanner checks trailing digits via Benford's law |
| `currency_fields_integer_cents` | Force all currency as integer cents |

This policy applies to **all** numeric fields in the result, not just
currency: `confidence` scores, `processing_duration_ms`, `row_count`, etc.

---

## 6. Sub-Agent Chains

Real-world agents are rarely a single model. A typical pipeline:

```
PDF → OCR (Tesseract) → Layout Detection (LayoutLM) → Table Extraction → Validation
       step_index: 0        step_index: 1                step_index: 2      step_index: 3
       deterministic        ml_structured                ml_structured       deterministic
```

Without explicit declaration of the full chain, a malicious orchestrator
could substitute an untrusted model mid-pipeline, inject an undeclared LLM,
or use a sub-agent that exfiltrates data via a separate network path.

### Contract Controls

The contract's `consumer.sub_agent_policy` governs multi-model composition:

```json
{
  "sub_agent_policy": {
    "allowed": true,
    "max_pipeline_steps": 5,
    "allowed_purposes": ["ocr", "layout_detection", "table_extraction", "validation"],
    "require_sub_agent_hashes": true,
    "approved_sub_agent_hashes": [ ... ],
    "cross_enclave_allowed": false,
    "llm_sub_agent_allowed": false
  }
}
```

| Field | Default | Purpose |
|---|---|---|
| `allowed` | `true` | If `false`, agent must not delegate to any sub-models |
| `max_pipeline_steps` | — | Maximum number of steps in the chain |
| `allowed_purposes` | — | Only these purposes are permitted (`ocr`, `layout_detection`, `table_extraction`, `classification`, `key_value_extraction`, `summarization`, `translation`, `validation`, `custom`) |
| `require_sub_agent_hashes` | `true` | Every sub-agent must have a verifiable `agent_hash` |
| `approved_sub_agent_hashes` | — | Only these specific binary hashes are allowed |
| `cross_enclave_allowed` | `false` | If `false`, all sub-agents must run in the same enclave |
| `llm_sub_agent_allowed` | `false` | If `false`, no sub-agent may be `llm_freeform` |

### Declaring the Chain

Each step in the pipeline must be declared in the result's
`attestation.claims.sub_agent_chain`:

```json
{
  "sub_agent_chain": [
    {
      "step_index": 0,
      "agent_type": "deterministic",
      "agent_id": "tesseract-ocr",
      "agent_hash": { "algorithm": "sha-256", "value": "..." },
      "agent_version": "5.3.0",
      "purpose": "ocr",
      "input_type": "raw_document",
      "output_type": "extracted_text",
      "enclave_shared": true,
      "network_access": false
    },
    {
      "step_index": 1,
      "agent_type": "ml_structured",
      "agent_id": "layoutlm-v3",
      "agent_hash": { "algorithm": "sha-256", "value": "..." },
      "agent_version": "3.0.0",
      "purpose": "layout_detection",
      "input_type": "extracted_text",
      "output_type": "structured_fields",
      "enclave_shared": true,
      "network_access": false
    }
  ]
}
```

### Rules

- If `require_sub_agent_hashes` is `true` (default), every entry must have a
  verifiable `agent_hash`.
- If `llm_sub_agent_allowed` is `false` (default), no entry may have
  `agent_type: "llm_freeform"`.
- Cross-enclave sub-agents (`enclave_shared: false`) must carry their own
  `separate_attestation`.
- The `sub_agent_chain_declaration` claim in `must_include` proves the chain
  was fully declared. Undeclared sub-agents are a contract violation.

---

## 7. Contract Compliance Checklist

Quick reference for agent developers. Verify each item before submitting a
result.

### Before Starting a Session

- [ ] Contract `status` is `"active"`
- [ ] Current time is within `permissions.valid_from` / `valid_until`
- [ ] Your `enclave_type` is in `attestation_requirements.enclave_types`
- [ ] Your `agent_hash` matches `consumer.agent_hash` (if specified)
- [ ] Your `agent_version` satisfies `consumer.agent_versions_allowed` (if specified)
- [ ] Session limit (`permissions.max_sessions`) has not been reached

### During Processing

- [ ] Only perform operations listed in `permissions.operations`
- [ ] Only access documents matching `permissions.document_filter` (if set)
- [ ] Network destinations match `allowed_destinations` in the contract
- [ ] If using sub-agents, the chain complies with `sub_agent_policy`
- [ ] Do not include raw document content in the result

### Redaction

- [ ] Apply the exact redaction method from `pii_redaction_rules` for each PII field
- [ ] Scan `pii_bearing` table columns for embedded PII (names in descriptions, etc.)
- [ ] `suppress` means `[REDACTED]`, not an empty string
- [ ] `mask_last_4` keeps only the last 4 characters visible

### Result Envelope

- [ ] Run all scanners listed in `result_scanning.required_scanners`
- [ ] Honor `scan_failure_action` (`block_result`, `flag_and_deliver`, `quarantine`)
- [ ] Numeric fields comply with `numeric_precision_policy.max_decimal_places`
- [ ] `pii_report.raw_content_included` is `false`
- [ ] Include `end_of_session_attestation` with matching measurement
- [ ] Include all claims required by `attestation_requirements.must_include`
- [ ] If sub-agents were used, include `sub_agent_chain` in attestation claims
- [ ] Result envelope validates against `schemas/result.schema.json`

---

## 8. Security Invariants

These invariants must hold for any conformant DSSP agent. Violating any of
them is a protocol-level security failure.

### Data Never Leaves the Owner

Raw document content must **never** appear in the result envelope. Only
structured extractions (fields, tables) with PII redacted per the contract
are permitted. The `pii_report.raw_content_included` field must be `false`.

### Attestation Proves Code Identity

The agent's `measurement` (MRENCLAVE for SGX, launch digest for Nitro) is a
cryptographic hash of the code running inside the enclave. The gateway
verifies this against the contract's `agent_hash` before granting a session.

### Measurement Stability

The end-of-session attestation measurement must match the start-of-session
measurement. A mismatch indicates the enclave was modified during processing
(potential tampering) and triggers a `violation.detected` audit event.

### Network Isolation

The agent must only communicate with destinations declared in the contract's
`allowed_destinations`. The sidecar verifier independently monitors all
network I/O and compares it against the agent's self-reported
`network_destinations` claim. A mismatch emits a
`sidecar.network_mismatch` audit event.

### Independent Scanning

Result scanners run as a **separate process** from the agent. The agent
cannot bypass or influence the scanner. Scanner binaries should be
independently attested (the contract may specify `approved_scanner_hashes`).

### Tamper-Proof Audit Trail

Every operation produces a Merkle-chained audit event. Each event includes
the hash of the previous event, making the chain tamper-evident. The audit
trail is immutable — events cannot be modified or deleted after creation.

### Sidecar Verification

The sidecar verifier runs in a **separate enclave** and independently
monitors:

- Network connections and destinations
- Memory allocation (RSS, peak)
- DNS queries
- File descriptor usage

If the sidecar's observations contradict the agent's self-reported claims,
a `sidecar.network_mismatch` or `sidecar.anomaly_detected` event is emitted.

---

## 9. Testing Your Agent

### Conformance Levels

The DSSP conformance suite defines four levels. Each level includes all tests
from the levels below it.

| Level | Marker | What it tests |
|---|---|---|
| **Core** | `@pytest.mark.core` | Schema validation, contract enforcement, audit chain integrity, PII redaction |
| **Attested** | `@pytest.mark.attested` | Hardware attestation verification, enclave type validation, certificate chains |
| **AI-Safe** | `@pytest.mark.ai_safe` | Agent type scanning requirements, privacy budgets, sub-agent chains, numeric precision |
| **Sovereign** | `@pytest.mark.sovereign` | Full compliance (Core + Attested + AI-Safe combined) |

### Running the Conformance Suite

```bash
cd reference/conformance
pip install -e ".[test]"

# Run all tests
pytest -v

# Run a specific level
pytest -v -m core
pytest -v -m ai_safe
pytest -v -m sovereign
```

### Validating Output Locally

Use the reference validator to check your result envelope against the JSON
schema before submitting:

```bash
cd reference/validator
python validate.py --schema ../../schemas/result.schema.json your-result.json
```

### Test Vectors

Interoperability test vectors are in
[`reference/test-vectors/`](reference/test-vectors/):

| Directory | What it tests |
|---|---|
| `canonical-json/` | RFC 8785 canonical JSON serialization |
| `hash-computation/` | SHA-256 hash computation over canonical JSON |
| `merkle-chain/` | Three-event Merkle chain with computed hashes |
| `pii-redaction/` | `mask_last_4`, `hash_sha256`, and `suppress` methods |
| `numeric-precision/` | Rounding, banker's rounding, significant digits |
| `sub-agent-chain/` | Valid and invalid pipeline configurations |

Each vector file contains `input`, `expected_output`, and `description`
fields for automated verification.

### Running the Full Stack

```bash
cd reference
docker compose up --build

# Gateway dashboard: http://localhost:8080
# MinIO console:     http://localhost:9101 (user: dssp-owner)
```

---

## 10. Common Pitfalls

| Symptom | Cause | Fix |
|---|---|---|
| `403 contract_violation` on session start | Attestation `enclave_type` not in contract's `enclave_types` list | Use a type the contract allows, or use `"sandbox"` in dev |
| `400 missing_field` on result submit | Required schema fields missing | Check `result.schema.json` — `pii_report`, `result_scan`, `attestation.claims` are all required |
| Gateway rejects result as "PII leak detected" | Result contains raw text or un-redacted PII | Apply redaction rules from `contract.restrictions.result_policy.pii_redaction_rules` to every field |
| Audit event shows `measurement_mismatch` | End-of-session measurement differs from start | In production this means the enclave was modified; in dev keep the same measurement value |
| `extraction_type` validation fails | Used free text instead of a known classification | Use values from the `DocumentClassification` enum in `common.schema.json` |
| Sub-agent chain rejected | `llm_sub_agent_allowed` is `false` but chain contains `llm_freeform` step | Remove the LLM sub-agent or get the contract updated |
| Numeric precision violation | Field has more decimal places than `max_decimal_places` | Round all numeric fields per the contract's `numeric_precision_policy` |
| Session expired during processing | Processing took longer than the token's `expires_at` | Request a longer session window or process fewer documents per session |

---

## 11. Going to Production

| Development | Production |
|---|---|
| `enclave_type: "sandbox"` | `"sgx"`, `"sev-snp"`, `"tdx"`, or `"nitro"` |
| Simulated attestation | Real hardware attestation via TEE SDK |
| MinIO on localhost | Owner's S3/Azure Blob/GCS with scoped SAS tokens |
| `httpx` to gateway on `:8080` | mTLS to gateway on `:443` |
| Regex-only PII scanner | spaCy/transformer NER + regex + statistical |
| Self-signed signatures | PKI signatures verifiable via attestation CA chain |
| No sidecar | Sidecar verifier in a separate enclave |

The protocol is the same — only the attestation backend and network transport
change. Your extraction logic, redaction pipeline, and result envelope
structure stay identical.

---

## Further Reading

- **Protocol specification:** [`spec/dssp-v0.1.md`](spec/dssp-v0.1.md)
- **Wire protocol (OpenAPI 3.1):** [`spec/dssp-api-v0.1.yaml`](spec/dssp-api-v0.1.yaml)
- **JSON Schemas:** [`schemas/`](schemas/) — formal schema for every DSSP artifact
- **Reference agent:** [`reference/agent/main.py`](reference/agent/main.py)
- **Attestation backends:** [`reference/agent/attestation.py`](reference/agent/attestation.py)
- **Scanner suite:** [`reference/scanner/`](reference/scanner/)
- **Sidecar verifier:** [`reference/sidecar/`](reference/sidecar/)
- **Tutorial (build your own agent):** [`examples/implement-your-own-agent/`](examples/implement-your-own-agent/)
- **Complete example:** [`examples/bank-statement-extraction/`](examples/bank-statement-extraction/)
- **Architecture overview:** [`ARCHITECTURE.md`](ARCHITECTURE.md)
- **Contributing:** [`CONTRIBUTING.md`](CONTRIBUTING.md)
