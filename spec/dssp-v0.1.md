# Document Sovereignty Protocol & Privacy — Specification v0.1-draft

**Status:** Draft  
**Date:** 2026-02-27  
**License:** Apache 2.0  
**Authors:** [Contributors](../CONTRIBUTORS.md)

---

## Abstract

The Document Sovereignty Protocol & Privacy (DSSP) is an open standard that defines how sensitive
documents are exposed, accessed, processed, and audited — without the documents ever
leaving infrastructure controlled by the document owner.

DSP enables organizations to share document processing capabilities with third-party
tools, auditors, and agents while maintaining full sovereignty over their data. No
document content or personally identifiable information (PII) crosses the owner's
infrastructure boundary. Only structured extraction results — with provable redaction —
leave the boundary.

## 1. Introduction

### 1.1 Problem Statement

Organizations in regulated industries (financial services, healthcare, legal, government)
must frequently share sensitive documents with external parties for processing: audit
firms extracting bank statement data, healthcare processors reading claims, legal teams
reviewing contracts.

Current approaches force a choice between:

1. **Upload to third-party SaaS** — Document content leaves the owner's control.
   Raises compliance, licensing, and "do you train on our data?" concerns.

2. **Manual exchange** — Email, file shares, physical media. No audit trail, no access
   control, no revocability.

3. **Vendor-specific portals** — Lock-in to a single provider's platform and terms.

DSP eliminates this choice by defining a protocol where:

- Documents stay on the owner's infrastructure.
- Processing happens in attested compute environments.
- Only structured, PII-redacted results exit the boundary.
- Every operation is cryptographically auditable.

### 1.2 Design Principles

1. **Data Residency** — Documents MUST NOT leave the owner's storage boundary.
2. **Processing Isolation** — Document content MUST only be accessed inside attested
   compute (enclaves or equivalent).
3. **Result Sanitization** — Only structured results exit the boundary — never raw
   content, never unredacted PII.
4. **Provable Integrity** — Every operation MUST produce a cryptographic attestation.
5. **Owner Sovereignty** — The document owner decides who can do what, and can revoke
   at any time.
6. **Defense in Depth** — No single mechanism is trusted alone. Redaction rules,
   result scanning, enclave attestation, sidecar verification, and privacy budgets
   form overlapping defenses.
7. **AI-Aware by Default** — The protocol explicitly addresses LLM/AI agent risks
   including free-text leakage, non-deterministic outputs, and prompt injection.

### 1.3 Terminology

| Term | Definition |
|------|-----------|
| **Owner** | The organization that owns and controls the documents |
| **Consumer** | An external organization that needs to process documents (e.g., audit firm) |
| **Agent** | Software that runs inside an attested enclave to process documents |
| **Agent Type** | Processing model: `deterministic`, `ml_structured`, or `llm_freeform` |
| **Gateway** | The DSP orchestration layer that manages manifests, contracts, and results |
| **Manifest** | Metadata describing available documents — never containing content |
| **Contract** | Policy defining what a consumer can do, enforced by the protocol |
| **Result Envelope** | Structured extraction output with attestation proof |
| **Result Scanner** | Independent process that inspects results for PII before they exit |
| **Sidecar Verifier** | Independent enclave co-process that monitors agent network/memory/syscalls |
| **Audit Event** | Immutable record of a protocol operation |
| **Enclave / TEE** | Trusted Execution Environment providing hardware-level isolation |
| **Attestation** | Cryptographic proof that code ran in an enclave with specific properties |
| **PII** | Personally Identifiable Information as defined by applicable regulation |
| **PII-bearing field** | A field that MAY contain embedded PII in free-text (e.g., transaction descriptions) |
| **Privacy Budget** | Quantitative limit on information extractable across sessions |
| **Document Sanitization** | Pre-processing that removes hidden content and injection patterns |
| **Split-Knowledge** | Architecture where no single party can reconstruct the full picture |

### 1.4 Notational Conventions

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be
interpreted as described in [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119).

## 2. Protocol Architecture

DSP consists of five layers, each independently specifiable:

```
┌───────────────────────────────────────────────────┐
│  Layer 4: AUDIT LEDGER                            │
│  Immutable chain of operation records             │
├───────────────────────────────────────────────────┤
│  Layer 3: RESULT ENVELOPE                         │
│  Structured extractions + attestation proofs      │
│  + result scanning verdicts                       │
├───────────────────────────────────────────────────┤
│  Layer 2: PROCESSING CONTRACT                     │
│  Permissions, restrictions, attestation policy    │
│  + AI-specific controls + privacy budget          │
├───────────────────────────────────────────────────┤
│  Layer 1: DOCUMENT MANIFEST                       │
│  Metadata catalog — never content                 │
├───────────────────────────────────────────────────┤
│  Layer 0: STORAGE BINDING                         │
│  Abstract interface to any storage backend        │
└───────────────────────────────────────────────────┘
```

### 2.1 Layer 0: Storage Binding

**Schema:** `storage-binding.schema.json`

DSSP does NOT mandate any storage technology. It defines an abstract interface with
four operations that any storage backend must implement:

1. `list_documents` — Enumerate documents and produce manifests (no content exposure)
2. `grant_access` — Issue scoped, time-limited tokens to attested enclaves
3. `read_document` — Serve encrypted content only to verified enclaves
4. `verify_integrity` — Confirm document hashes match stored content

**Supported adapters** include S3-compatible (MinIO, AWS S3, SeaweedFS, Ceph RGW),
Azure Blob Storage, Google Cloud Storage, POSIX filesystems, NFS, and GlusterFS.
Customers MAY implement custom adapters.

**Security requirements:**
- `read_document` MUST verify the caller's attestation token before serving content.
- Access tokens MUST be scoped to specific documents and operations.
- Access tokens MUST expire. Maximum TTL SHOULD be specified in the processing contract.
- TLS MUST be used for all storage communications in production deployments.

### 2.2 Layer 1: Document Manifest

**Schema:** `manifest.schema.json`

A manifest describes documents available for processing. It is the discovery mechanism —
it tells consumers "here's what exists and what you can do with it."

**Critical constraint:** A manifest MUST NOT contain document content, text excerpts,
image thumbnails, or any data from which PII could be inferred.

A manifest contains for each document:
- Opaque document ID (not the filename)
- Classification (e.g., `financial/bank-statement`)
- Sensitivity level
- Format (MIME type)
- Content hash (for integrity verification)
- Declared PII field types (tells processors what to expect)
- Allowed and denied operations

### 2.3 Layer 2: Processing Contract

**Schema:** `contract.schema.json`

A processing contract is created by the document owner. It defines:

**Permissions:**
- Which operations the consumer can perform
- Which documents (by classification, tag, or explicit ID)
- Maximum session duration and document count
- Validity period

**Restrictions:**
- Network policy (deny all egress, or allow-list specific destinations)
- Storage policy (memory-only, encrypted ephemeral, or encrypted persistent)
- Result policy with PII redaction rules per field type
- Custom regex-based redaction patterns
- Result scanning requirements (§4.4)
- Document sanitization policy (§4.5)
- Privacy budget (§4.6)
- Numeric precision policy (§4.10) — anti-steganographic controls
- Gateway visibility controls (§5.3)

**AI Agent Restrictions (§4.3):**
- Agent type classification determines scanning rigor
- LLM-specific free-text policies
- Mandatory NER scanning for `llm_freeform` agents
- Sub-agent composition policy (§4.9): which sub-models are allowed, purposes, hash requirements

**Attestation requirements:**
- Accepted enclave types (SGX, SEV-SNP, TDX, Nitro, CCA)
- Required attestation claims
- Measurement signing authorities
- Attestation freshness window
- Runtime verification controls (§4.7)

Contracts are versioned. The owner can update, suspend, or revoke contracts at any
time. Revocation MUST prevent new processing sessions immediately.

#### 2.3.1 Revocation Propagation

Contract revocation MUST propagate from the owner through the gateway to active
enclaves within a bounded time window:

- The gateway MUST poll for contract status updates at least every
  `attestation_freshness_seconds` (default: 300s).
- Alternatively, implementations MAY use a push mechanism (webhook, gRPC stream,
  or WebSocket) for lower-latency propagation.
- Upon detecting a revocation, the gateway MUST reject new session requests for
  the revoked contract immediately.
- For running sessions: the gateway MUST send a termination signal to the enclave
  within `attestation_freshness_seconds` of revocation.
- The maximum revocation propagation delay is `2 × attestation_freshness_seconds`.
  Implementations SHOULD document their actual propagation latency.
- A `contract.revoked` audit event MUST be emitted when revocation is processed,
  followed by `session.terminated` events for any active sessions that were
  terminated as a result.

### 2.4 Layer 3: Result Envelope

**Schema:** `result.schema.json`

The result envelope is the ONLY artifact that crosses from the owner's infrastructure
to the outside world. It contains:

**Structured extractions:**
- Key-value fields (with PII redacted per contract rules)
- Tables (with column-level PII handling and `pii_bearing` annotations)
- Classification results with confidence scores
- Self-validation checks

**Attestation proof:**
- Enclave type and measurement
- Agent binary hash (proves which code ran)
- Input document hashes (proves which documents were read)
- Output result hash (proves result integrity)
- Network connection log (proves no unauthorized egress)
- Sub-agent chain (§4.9): ordered list of all sub-models used, with hashes

**Result scan report (§4.4):**
- Verdicts from each independent scanner (regex, NER, statistical)
- Fields modified by scanning (separate from agent-applied redaction)
- Overall pass/fail determination

**End-of-session attestation (§4.7):**
- Fresh enclave measurement at session end
- Proof that the measurement matches the start

**PII handling report:**
- Fields encountered vs. fields redacted
- Redaction methods applied
- Compliance status (compliant / violation_detected / unknown)

### 2.5 Layer 4: Audit Ledger

**Schema:** `audit-event.schema.json`

Every DSP operation produces an audit event. Events form a Merkle chain — each
event references the hash of the previous event, making the ledger tamper-evident.

#### 2.5.1 Canonical Serialization

All hash computations over JSON objects — including `event_hash`, `previous_event_hash`,
`output_result_hash`, and any other hash referenced in this specification — MUST use
[RFC 8785 (JSON Canonicalization Scheme)](https://www.rfc-editor.org/rfc/rfc8785) to
produce a deterministic byte sequence before hashing.

This ensures that two independent implementations computing a hash over the same
logical JSON object will always produce the same hash value, which is essential for
Merkle chain interoperability and cross-implementation verification.

Implementations MUST NOT rely on property insertion order, whitespace formatting,
or locale-specific number serialization. RFC 8785 defines canonical treatment of:
- Object key ordering (lexicographic by Unicode code point)
- Number representation (no trailing zeros, no positive sign, no leading zeros)
- String escaping (minimal escaping)
- No whitespace between tokens

Event types cover the full lifecycle:
- Manifest creation, updates, expiry
- Contract creation, updates, suspension, revocation
- Session start, completion, failure, termination
- Document access and processing
- Result production, delivery, scanning outcomes
- Attestation verification (start, heartbeat, end-of-session)
- Document sanitization and injection detection
- Sidecar verifier anomaly detection
- Privacy budget consumption and exhaustion
- Violation detection and escalation

The audit ledger is stored on the owner's infrastructure. Events MAY be replicated
to the DSSP Gateway for dashboard visibility, but replicated events MUST NOT contain
PII.

## 3. Trust Model

```
                    DOCUMENT OWNER
                         │
                  trusts nothing
                    by default
                         │
            ┌────────────┼───────────────┐
            ▼            ▼               ▼
      DSSP Gateway   Processing Agent   Consumer App
            │            │               │
       Can see:     Can see:         Can see:
       manifests    documents        result envelopes
       audit logs   (in enclave      manifests (filtered)
       results       only)
       (filtered)        │               │
            │       Cannot see:     Cannot see:
       Cannot see:  other docs      documents
       documents    network         raw content
       PII          owner keys      other consumers
       raw text
```

### 3.1 Attestation Chain

1. Agent boots inside a TEE (enclave).
2. Platform provides hardware attestation (CPU-signed measurement).
3. Agent presents attestation to the storage adapter via `grant_access`.
4. Storage adapter verifies attestation against the contract's requirements.
5. If verified, storage issues a scoped access token.
6. **Document sanitization** runs before the agent processes content (§4.5).
7. Agent processes documents, produces a result envelope.
8. **Result scanning** independently inspects the result for PII leakage (§4.4).
9. Result envelope includes the attestation proof and scan verdicts.
10. **End-of-session attestation** proves enclave integrity throughout (§4.7).
11. Gateway and owner can independently verify the attestation chain.

### 3.2 What Each Party Can Verify

| Verifier | Can verify |
|----------|-----------|
| **Owner** | Full audit trail, attestation proofs, result integrity, PII compliance, scan verdicts, privacy budget consumption |
| **Consumer** | Result integrity, attestation proof (proves their agent ran correctly) |
| **Regulator** | Audit chain integrity, PII handling compliance, data residency, privacy budget adherence |
| **Gateway** | Attestation validity, contract compliance, result schema conformance, scan pass/fail |

### 3.3 Cryptographic Requirements

This section specifies the cryptographic algorithms and formats used throughout
the protocol.

#### 3.3.1 Signature Algorithms

| Algorithm | Status | Use Case |
|-----------|--------|----------|
| Ed25519 | REQUIRED | Default signature algorithm. All implementations MUST support Ed25519. |
| ECDSA P-256 (secp256r1) | RECOMMENDED | Interoperability with existing PKI infrastructure. |
| RSA-2048+ | MAY | Legacy compatibility. Key size MUST be at least 2048 bits. |

Implementations MUST support Ed25519. Implementations SHOULD support ECDSA P-256.
If multiple algorithms are supported, the attestation token MUST indicate which
algorithm was used.

#### 3.3.2 Signature Input

The input to any signature operation MUST be the [RFC 8785](https://www.rfc-editor.org/rfc/rfc8785)
canonical JSON serialization of the object being signed, **excluding** the `signature`
field itself. Specifically:

1. Remove the `signature` field from the JSON object (if present).
2. Serialize the remaining object using RFC 8785 canonical form.
3. Compute the signature over the resulting byte sequence.

This applies to `AttestationToken.signature`, `end_of_session_attestation.signature`,
`SubAgentAttestation.separate_attestation.signature`, and any other signature field
defined in this specification.

#### 3.3.3 Encoding Formats

| Data | Format |
|------|--------|
| Signatures | Base64url encoding ([RFC 4648 §5](https://www.rfc-editor.org/rfc/rfc4648#section-5)), no padding |
| Hash digests | Hex-encoded lowercase string (as defined in `HashDigest`) |
| Public keys (exchange) | [JWK (RFC 7517)](https://www.rfc-editor.org/rfc/rfc7517) |
| Certificates | PEM-encoded X.509 |

#### 3.3.4 Hash Algorithms

| Algorithm | Status | Use Case |
|-----------|--------|----------|
| SHA-256 | REQUIRED | Baseline for Merkle chain (`event_hash`, `previous_event_hash`), document integrity, result integrity |
| SHA-384 | MAY | Higher security margin where required by policy |
| SHA-512 | MAY | Higher security margin where required by policy |
| BLAKE3 | MAY | Performance-optimized alternative for high-throughput scenarios |

The Merkle chain in the audit ledger MUST use SHA-256 as the baseline hash algorithm.
Implementations MAY support additional algorithms but MUST always support SHA-256
for interoperability.

## 4. PII Safety

PII safety is not a feature — it is enforced at every protocol layer through
multiple overlapping defenses.

| Layer | Protection |
|-------|-----------|
| **Manifest** | Metadata only. No content, no snippets, no previews. |
| **Contract** | `pii_redaction_rules` force masking/hashing before results leave enclave |
| **Sanitization** | Documents stripped of hidden content and injection patterns before agent sees them |
| **Agent** | Applies redaction rules from contract |
| **Result Scanner** | Independent process re-checks results for PII leakage (especially free-text) |
| **Result** | `pii_report` + `result_scan` declare what was redacted and how. Machine-verifiable. |
| **Privacy Budget** | Statistical limits prevent re-identification across sessions |
| **Audit** | Events contain IDs and hashes — never content. Even filenames can be hashed. |
| **Storage** | Documents encrypted at rest with customer-held keys |

### 4.1 Default-Deny PII Policy

PII fields not explicitly listed in the contract's `pii_redaction_rules` with a
method of `allow` MUST be suppressed (removed entirely) from results.

### 4.2 Redaction Methods

| Method | Behavior |
|--------|----------|
| `allow` | Pass through unchanged (only for fields the owner explicitly permits) |
| `mask_last_4` | Replace all but last 4 characters with `*` |
| `mask_first_6` | Replace first 6 characters with `*` |
| `mask_all` | Replace entire value with `****` |
| `hash_sha256` | Replace with SHA-256 hash (allows cross-reference without revealing value) |
| `hash_blake3` | Replace with BLAKE3 hash |
| `round_thousands` | Round numeric value to nearest thousand |
| `round_millions` | Round numeric value to nearest million |
| `range_bucket` | Replace with a range (e.g., "$1M-$5M") |
| `suppress` | Remove entirely from output |
| `tokenize` | Replace with a reversible token (owner can de-tokenize) |
| `k_anonymize` | Apply k-anonymity transformation |

### 4.3 Agent Type Classification

Agents MUST declare their processing model. The agent type determines minimum
scanning requirements and privacy budget enforcement:

| Agent Type | Description | Minimum Scanning | Privacy Budget |
|-----------|------------|-----------------|---------------|
| `deterministic` | Rule-based extraction (regex, template matching). Outputs are predictable and type-safe. | `regex` scanner | RECOMMENDED |
| `ml_structured` | ML model that produces typed fields/tables only. No free-text output. | `regex` + `ner` | RECOMMENDED for pii-high |
| `llm_freeform` | LLM that MAY produce free-text output. Non-deterministic. Risk of PII in generated text. | `regex` + `ner` + `llm_output_filter` REQUIRED | REQUIRED |

**LLM-specific risks:**
- LLMs may memorize training data and reproduce PII in generated text.
- Free-text fields (descriptions, summaries) may contain embedded PII.
- Non-deterministic outputs make testing insufficient — runtime scanning is essential.
- Prompt injection via document content can manipulate LLM behavior.

### 4.4 Result Scanning

Result scanning is a **separate, independent process** (not the agent itself) that
inspects result content for PII leakage **before** it exits the enclave boundary.

**Requirements:**
- `result_scanning.enabled` MUST be `true` when `agent_type` is `llm_freeform`.
- RECOMMENDED for all other agent types.
- Each scanner runs independently and produces a verdict.
- If ANY scanner fails, the result MUST be handled per `scan_failure_action`:
  `block_result` (default), `flag_and_deliver`, or `quarantine`.

**Scanner types:**

| Scanner | Purpose | When required |
|---------|---------|--------------|
| `regex` | Pattern-based PII detection (IBANs, SSNs, credit cards) | All agent types |
| `ner` | Named Entity Recognition (persons, orgs, locations) | `ml_structured`, `llm_freeform` |
| `llm_output_filter` | Specialized model for PII in generated free-text | `llm_freeform` |
| `statistical` | Detects re-identification risk (uniqueness analysis) | RECOMMENDED for pii-high+ |

**Attestation requirement:** Scanner binaries SHOULD be attested separately
from the agent. The contract MAY specify `approved_scanner_hashes` that the
scanner MUST match.

### 4.5 Document Sanitization

Document sanitization is a **pre-processing layer** that cleans documents before
the agent processes them. It is the primary defense against **prompt injection
attacks** where malicious content in documents manipulates LLM behavior.

**Sanitization steps:**
1. Strip hidden text layers, white-on-white text, zero-width characters
2. Strip JavaScript from PDFs
3. Strip embedded files and attachments
4. Normalize Unicode to NFC form (prevents homoglyph attacks)
5. Detect and flag/remove known prompt injection patterns
6. Truncate pages exceeding `max_text_length_per_page` (prevents token-stuffing)

**Requirements:**
- RECOMMENDED when `agent_type` is `llm_freeform`.
- The sanitizer binary SHOULD be attested (contract MAY specify `sanitizer_hash`).
- The contract's `attestation_requirements.must_include` SHOULD include
  `sanitizer_execution_proof` to prove sanitization actually ran.

### 4.6 Privacy Budget

The privacy budget prevents **re-identification attacks** where an adversary
combines results from multiple sessions to identify individuals.

**Controls:**

| Control | Purpose |
|---------|---------|
| `epsilon` / `delta` | Differential privacy budget. Limits total information extractable. |
| `k_anonymity_min` | Result fields must be indistinguishable from k-1 others. |
| `max_unique_values_per_field` | Prevents exact figures from being unique identifiers. |
| `aggregation_minimum_records` | No field from fewer than N source documents. |
| `budget_window` | Time window for budget tracking (per_session, per_day, per_contract, lifetime). |

**Requirements:**
- REQUIRED when `agent_type` is `llm_freeform`.
- RECOMMENDED for all agent types processing `pii-high` or `pii-critical` documents.
- The gateway MUST track budget consumption across sessions and reject requests that
  would exceed the budget.

### 4.7 Runtime Verification

Attestation at session start proves the enclave booted correctly. But an agent
could be compromised **during** processing. Runtime verification addresses this gap.

**End-of-session attestation:**
- Agent MUST produce a **fresh** hardware attestation at session end.
- The end measurement MUST match the start measurement. A mismatch indicates
  potential tampering and MUST trigger a `violation.detected` audit event.
- The result envelope carries the end-of-session attestation.

**Periodic heartbeats:**
- The contract MAY require attested heartbeats at a specified interval.
- Missing heartbeats MUST trigger session termination.

**Sidecar verifier:**
- An independent co-processor running in a **separate enclave**.
- Monitors network I/O, memory allocation, DNS queries, and syscalls.
- Independently logs all network activity and compares against the agent's
  self-reported claims.
- If the sidecar detects a mismatch (e.g., agent claims 0 network connections
  but the sidecar observed 5), a `sidecar.network_mismatch` event is emitted.
- The contract MAY require a sidecar (`sidecar_verifier.required: true`).

### 4.8 PII-Bearing Columns

Some table columns contain **embedded PII in free-text** even though the column
itself is not a dedicated PII field. Common examples:

- `description` columns in bank statement transactions (contain counterparty names,
  addresses, invoice numbers)
- `memo` and `notes` fields
- `reference` columns with free-text references

Columns MUST declare `pii_bearing: true` when they MAY contain embedded PII.
Values in `pii_bearing` columns MUST be scanned by NER before leaving the enclave.

### 4.9 Multi-Model Composition (Sub-Agent Chain)

Real-world document processing agents are rarely a single model. A typical pipeline:

```
PDF → OCR (Tesseract) → Layout Detection (LayoutLM) → Table Extraction → Validation
```

Without explicit declaration of the full chain, a malicious orchestrator could:
- Substitute an untrusted model mid-pipeline
- Inject an undeclared LLM sub-agent into an `ml_structured` pipeline
- Use a sub-agent that phones home via a separate network path

**Sub-Agent Policy (contract):**

The contract's `consumer.sub_agent_policy` controls:
- Whether sub-agents are allowed at all
- Maximum pipeline steps
- Which purposes are permitted (OCR, classification, etc.)
- Whether LLM sub-agents are allowed (RECOMMENDED: `false` unless scanning covers the full pipeline)
- Whether cross-enclave invocation is permitted
- Approved sub-agent binary hashes

**Sub-Agent Chain (result attestation):**

The result envelope's `attestation.claims.sub_agent_chain` is an ordered array of
`SubAgentAttestation` records — one per pipeline step. Each declares:
- Agent type, hash, and version
- Purpose and input/output types
- Whether it ran in the same or a separate enclave
- Processing time for that step

**Requirements:**
- If `sub_agent_policy.require_sub_agent_hashes` is `true` (default), every entry
  MUST have a verifiable `agent_hash`.
- If `sub_agent_policy.llm_sub_agent_allowed` is `false` (default), no entry MAY
  have `agent_type: "llm_freeform"`.
- The `sub_agent_chain_declaration` claim in `must_include` proves the chain was
  fully declared. Undeclared sub-agents indicate a contract violation.
- Cross-enclave sub-agents MUST carry their own `separate_attestation`.

### 4.10 Numeric Precision and Anti-Steganographic Controls

A subtle exfiltration vector: an adversarial agent can encode information in the
**trailing digits** of numeric fields. For example, a balance of `1,247,832.50`
contains no hidden information — but `1,247,832.5031742` encodes ~16 extra bits
in the trailing digits that no human would notice.

With hundreds of numeric fields per result (amounts, balances, running totals,
confidence scores), an agent could exfiltrate thousands of bits per session.

**Numeric Precision Policy (contract):**

The contract's `result_policy.numeric_precision_policy` controls:

| Control | Purpose |
|---------|---------|
| `max_decimal_places` | Maximum decimals for currency fields (default: 2) |
| `max_significant_digits` | Maximum significant digits for any numeric field |
| `enforce_standard_rounding` | Require IEEE 754 round-half-to-even (prevents encoding via rounding direction) |
| `detect_entropy_anomaly` | Scanner checks trailing digits for non-natural distribution (Benford's law) |
| `currency_fields_integer_cents` | Force all currency as integer cents (eliminates decimals) |

**How it works:**
1. The agent produces results with numeric fields.
2. The result scanner (if `detect_entropy_anomaly` is enabled) runs a statistical
   test on trailing digits. Natural financial data follows Benford's law; artificially
   encoded data does not.
3. The scanner also verifies all numeric fields comply with `max_decimal_places`
   and `max_significant_digits`. Non-compliant values are rounded.
4. If `enforce_standard_rounding` is true, the scanner verifies rounding direction
   matches IEEE 754 round-half-to-even (no systematic bias exploitable for encoding).

**Scope of application:**

The `numeric_precision_policy` MUST apply to ALL numeric fields in the result
envelope, not only currency-related fields. This includes:

- `confidence` scores (e.g., `0.9700000000000001` MUST be rounded to `0.97`
  when `max_decimal_places` is 2)
- `processing_duration_ms` (timing channel)
- `memory_peak_bytes` (encoding channel)
- `row_count` and other count fields
- Any numeric value in `fields` or `tables` within extractions

Each of these fields represents a potential covert channel. An IEEE 754 double
has 52 bits of mantissa — every unrestricted numeric field can leak up to 52
bits per value. With hundreds of fields per result, this is a significant
exfiltration vector.

**RECOMMENDED defaults for financial data:**
```json
{
  "max_decimal_places": 2,
  "max_significant_digits": 12,
  "enforce_standard_rounding": true,
  "detect_entropy_anomaly": true,
  "currency_fields_integer_cents": false
}
```

## 5. Architecture

### 5.1 Enclave Requirements

DSP REQUIRES hardware-attested enclaves for all non-public documents. The following
enclave types are supported:

| Type | Platform | Notes |
|------|---------|-------|
| `sgx` | Intel SGX | Process-level isolation, smallest TCB |
| `sev-snp` | AMD SEV-SNP | VM-level isolation, full memory encryption |
| `tdx` | Intel TDX | VM-level isolation, trust domain extensions |
| `nitro` | AWS Nitro Enclaves | Cloud-specific, no persistent storage |
| `cca` | Arm CCA | Realm-based isolation |

**The `sandbox` type** is available for development and testing only:
- MUST NOT be used in production.
- Contracts using `sandbox` MUST set `sensitivity_max` to `public` or `internal`.
- Conformance tests MUST reject `sandbox` for `pii-low` or higher sensitivity.

**Note:** The `enclave_type: "none"` option was removed in v0.1.1. All processing
of non-public documents REQUIRES attested compute.

### 5.2 Processing Flow

```
OWNER INFRASTRUCTURE                           CONSUMER
┌─────────────────────────────────────────┐    ┌──────────┐
│                                         │    │          │
│  Storage ──► Sanitizer ──► Agent (TEE) ─┼──► │  Result  │
│     ▲            │            │    │    │    │ Envelope │
│     │            ▼            ▼    │    │    └──────────┘
│   Docs    Audit Event    Scanner   │    │
│                            │       │    │
│                            ▼       ▼    │
│                        Verdict  EoS     │
│                                Attest   │
└─────────────────────────────────────────┘
```

1. Owner creates manifest and contract
2. Agent boots in enclave, attests to storage adapter
3. Storage issues scoped access token
4. **Sanitizer** cleans documents (strips hidden content, injection patterns)
5. Agent processes sanitized documents
6. Agent produces result with PII redaction per contract rules
7. **Result scanner** independently checks result for PII leakage
8. Agent produces **end-of-session attestation**
9. Result envelope (with scan verdicts + EoS attestation) exits boundary
10. Audit events recorded for every step

### 5.3 Gateway Isolation (Split-Knowledge Model)

The DSSP Gateway orchestrates the protocol but SHOULD NOT accumulate enough data
to re-identify individuals or correlate results across engagements.

**Gateway visibility is configurable per contract:**

| Data Type | Visibility Options |
|----------|-------------------|
| Manifests | `full`, `summary_only`, `none` |
| Results | `full`, `metadata_only`, `verdict_only`, `none` |
| Audit Events | `full`, `summary_only`, `none` |

**Cross-engagement correlation:**
- `cross_engagement_correlation: false` (default) means the gateway MUST NOT
  correlate data across different engagements from the same owner.
- Implementations SHOULD use per-engagement encryption keys.
- This prevents the gateway from building a statistical profile of the owner's
  documents across multiple audit periods.

**RECOMMENDED default for regulated data:**
```json
{
  "manifests": "summary_only",
  "results": "metadata_only",
  "audit_events": "summary_only",
  "cross_engagement_correlation": false
}
```

### 5.4 Session Lifecycle and Recovery

A DSSP processing session begins when the gateway creates a session context
(binding a contract, agent, and set of documents) and ends when the agent
produces a result or the session fails.

#### 5.4.1 Session States

```
        ┌───────────┐
        │  created   │
        └─────┬─────┘
              │ agent attests
              ▼
        ┌───────────┐
        │  active    │◄── heartbeats
        └─────┬─────┘
              │
    ┌─────────┼──────────┐
    ▼         ▼          ▼
┌────────┐ ┌────────┐ ┌────────────┐
│completed│ │ failed │ │ terminated │
└────────┘ └────────┘ └────────────┘
```

- **created** — Session allocated, waiting for agent attestation.
- **active** — Agent has attested and is processing documents.
- **completed** — Agent produced a result and end-of-session attestation.
- **failed** — Session ended due to agent crash, unrecoverable error, or timeout.
- **terminated** — Session ended due to external action (contract revocation,
  missing heartbeat, sidecar anomaly).

#### 5.4.2 Recovery Semantics

Sessions are NOT resumable. A crashed or terminated session MUST be treated
as failed. Specifically:

- A failed session MUST produce a `session.failed` audit event with the
  failure reason.
- Partial results from a failed session MUST NOT be delivered to the consumer.
  Any partial state MUST be discarded.
- The consumer MAY start a new session under the same contract (if still active
  and within session limits).
- The contract's `max_concurrent_sessions` limit counts sessions in `created`
  and `active` states. Sessions in `failed` or `terminated` state MUST be
  cleaned up within `attestation_freshness_seconds` to free the slot.

#### 5.4.3 Result Delivery

Result delivery is idempotent:

- The gateway assigns each result a unique `result_id`.
- The consumer MAY request the same result multiple times via `GET /result/{id}`.
- If the consumer does not acknowledge receipt, the gateway MAY retry delivery.
- The result MUST NOT change between retries (same content, same hash).
- Results MUST be available for retrieval for at least the contract's
  `valid_until` timestamp.

#### 5.4.4 Timeout Handling

- If a session exceeds `max_session_duration_seconds`, the gateway MUST
  transition it to `terminated` state.
- A `session.timeout` audit event MUST be emitted.
- The gateway MUST instruct the enclave to halt processing.
- If the agent produces a result after timeout, the result MUST be rejected.

## 6. Conformance

### 6.1 Conformance Levels

| Level | Requirements |
|-------|-------------|
| **DSSP Core** | Layers 1-4 schemas. Manifests, contracts, results, audit events. |
| **DSSP Attested** | DSSP Core + hardware attestation (Layer 2 attestation_requirements enforced) |
| **DSSP Sovereign** | DSSP Attested + customer-managed encryption keys + data residency enforcement |
| **DSSP AI-Safe** | DSSP Attested + mandatory result scanning + NER + privacy budget + document sanitization |

### 6.2 Progressive Adoption Path

DSSP is designed to be adopted incrementally. Each conformance level builds on
the previous one, and implementations can start simple and add capabilities
over time.

#### Getting Started (30 minutes)

1. Install the `dssp-gateway` reference implementation.
2. Create a manifest from a folder of sample documents.
3. Create a processing contract with basic permissions.
4. Run the demo agent against the sample documents.
5. View the result envelope and audit trail.

See the `reference/sandbox/` Docker Compose demo for a fully working example.

#### DSSP Core (1 day integration)

Requirements:
- Implement or integrate `dssp-gateway` with your storage backend.
- Use the MinIO adapter or write a custom storage adapter implementing the
  four required operations (list, grant, read, verify).
- Deploy a `deterministic` agent for structured extraction.
- Enable `regex` result scanning.
- Verify audit chain integrity with the conformance test suite.

#### DSSP Attested (1 week integration)

Requirements (in addition to DSSP Core):
- Set up a TEE environment (AWS Nitro Enclaves, Azure Confidential Computing,
  Intel SGX, or AMD SEV-SNP).
- Configure `attestation_requirements` in contracts with real enclave types
  (not `sandbox`).
- Deploy the agent inside the enclave with proper attestation.
- Enable end-of-session attestation to prove enclave integrity.
- Configure periodic heartbeats for long-running sessions.

#### DSSP AI-Safe (2 week integration)

Requirements (in addition to DSSP Attested):
- Integrate NER scanning (Microsoft Presidio or equivalent).
- Configure privacy budgets for contracts processing PII-high+ documents.
- Enable document sanitization (injection pattern detection, hidden text stripping).
- Set up the sidecar verifier for high-sensitivity workloads.
- Configure `numeric_precision_policy` for anti-steganographic controls.
- If using `llm_freeform` agents, add the `llm_output_filter` scanner.

#### DSSP Sovereign (ongoing)

Requirements (in addition to DSSP AI-Safe):
- Deploy with customer-managed encryption keys.
- Configure `data_residency` zones and verify documents never leave the zone.
- Enable split-knowledge gateway isolation (`metadata_only` or `verdict_only`
  visibility for results).
- Disable cross-engagement correlation.
- Conduct regular attestation audits with independent verifiers.

### 6.3 Conformance Testing

A conformance test suite (published separately) validates implementations against:

1. **Schema conformance** — All messages validate against the JSON schemas.
2. **PII safety** — Results MUST NOT contain PII fields that should be redacted.
3. **Result scan validation** — Scan verdicts MUST be present when required by contract.
4. **Audit integrity** — Event chain hashes MUST be correct and continuous.
5. **Contract enforcement** — Operations outside the contract MUST be rejected.
6. **Attestation verification** — Invalid attestations MUST be rejected.
7. **End-of-session attestation** — Measurement MUST match start measurement.
8. **Privacy budget** — Requests exceeding budget MUST be rejected.
9. **Enclave type constraints** — `sandbox` MUST be rejected for pii-low+.
10. **Agent type scanning** — `llm_freeform` MUST have NER scanning enabled.

## 7. Security Considerations

### 7.1 Threat Model

| Threat | Mitigation |
|--------|-----------|
| Malicious agent exfiltrates data via network | Contract `network_policy` with allow-list; sidecar verifier cross-checks |
| Agent stores data to disk and retrieves later | Contract `storage_policy: memory_only`; enclave prevents disk access |
| LLM embeds PII in free-text "description" fields | Result scanner with NER detects and redacts; `pii_bearing` column flag |
| Result contains hidden PII in "innocuous" fields | Multi-scanner pipeline (regex + NER + statistical) |
| Manifest reveals PII through document metadata | Manifest filenames are replaced with opaque IDs; no content fields |
| Audit ledger tampered to hide access | Merkle chain makes tampering detectable |
| Replay attack using old attestation | `attestation_freshness_seconds` limits token age |
| Enclave compromised during processing | End-of-session attestation detects measurement mismatch |
| Agent lies about network activity | Sidecar verifier independently monitors and cross-checks |
| Re-identification via aggregated results | Privacy budget (k-anonymity, differential privacy) limits extraction |
| Prompt injection via malicious document content | Document sanitization strips injection patterns before agent sees them |
| Gateway correlates results across engagements | Split-knowledge model with per-engagement keys; configurable visibility |
| Agent runs without enclave in production | `enclave_type: "none"` removed; `sandbox` rejected for pii-low+ |
| Steganographic exfiltration via numeric precision | `numeric_precision_policy` limits trailing digits; `detect_entropy_anomaly` flags non-natural distributions |
| Undeclared sub-model in multi-model pipeline | `sub_agent_chain` declaration required; `sub_agent_policy` restricts allowed sub-agents and purposes |
| Hidden LLM in a "deterministic" pipeline | `sub_agent_policy.llm_sub_agent_allowed: false` blocks LLM sub-agents; chain attestation makes substitution detectable |

### 7.2 Known Limitations

1. **Side-channel attacks** on enclaves (Spectre, etc.) are hardware-level risks that
   DSP cannot fully mitigate. Implementations SHOULD follow platform-specific
   hardening guides.

2. **Result inference** — Even with redacted PII and privacy budgets, sufficiently
   detailed structured results could allow re-identification in extreme cases.
   Owners SHOULD consider the sensitivity of allowed fields in aggregate.

3. **Agent trustworthiness** — DSP proves the agent ran specific code in an enclave.
   It does not prove the code is free of bugs or malicious logic. Code auditing
   remains the owner's responsibility.

4. **NER model limitations** — Named Entity Recognition is not perfect. Novel PII
   patterns, multilingual content, and domain-specific terminology may evade detection.
   The multi-scanner pipeline mitigates this but cannot guarantee zero false negatives.

5. **Sidecar overhead** — Running a sidecar verifier in a separate enclave adds
   computational and operational overhead. This is acceptable for high-sensitivity
   workloads but may be excessive for `public` or `internal` documents.

6. **Privacy budget tracking** — Budget enforcement requires a stateful component
   (typically the gateway) that tracks consumption across sessions. This introduces
   a single point of failure for budget enforcement.

## 8. Regulatory Compliance Mapping

| Regulation | DSP Feature |
|-----------|------------|
| GDPR Art. 5(1)(f) | Enclave attestation, encryption at rest, result scanning |
| GDPR Art. 25 | Data protection by design: default-deny PII, privacy budget |
| GDPR Art. 28 | Processing contract defines exact scope |
| GDPR Art. 30 | Audit ledger with full chain |
| GDPR Art. 35 | Privacy budget supports DPIA for automated processing |
| GDPR Art. 44-49 | Documents never leave data_residency zone |
| HIPAA Security Rule | PHI covered by pii_redaction_rules + NER scanning |
| PCI DSS Req. 3 | Card numbers masked via mask_last_4, regex scanner catches stray PANs |
| SOC 2 Type II | Attestation proves control enforcement; sidecar verifies runtime |
| SOX Section 404 | Immutable audit trail for financial data |
| NIS2 (EU) | Customer retains full sovereignty; enclave-only processing |
| ISAE 3402 | Full audit trail per engagement |
| AI Act (EU) Art. 15 | Result scanning provides transparency for AI-generated outputs |

## 9. Versioning

This specification uses semantic versioning:

- **Major** version: Breaking changes to schemas or protocol behavior.
- **Minor** version: Backward-compatible additions (new fields, new event types).
- **Patch** version: Clarifications and editorial corrections.

All messages in a DSSP session MUST use the same major version. Implementations
SHOULD accept messages with the same major version but different minor versions.

### 9.1 Changelog

| Version | Change |
|---------|--------|
| 0.1.1 | Added `AgentType` enum; `enclave_type: "none"` removed, replaced by `sandbox` for dev only |
| 0.1.1 | Added result scanning (`result_scan`) as required field in result envelope |
| 0.1.1 | Added `end_of_session_attestation` to result envelope |
| 0.1.1 | Added `pii_bearing` flag to `ExtractedTable` column definitions |
| 0.1.1 | Added `document_sanitization` to contract restrictions |
| 0.1.1 | Added `privacy_budget` to contract restrictions |
| 0.1.1 | Added `gateway_visibility` for split-knowledge model |
| 0.1.1 | Added `sidecar_verifier` and `runtime_verification` to attestation requirements |
| 0.1.1 | Added new audit event types: `sanitization.*`, `sidecar.*`, `privacy_budget.*`, `attestation.end_of_session`, `result.scan_passed/failed` |
| 0.1.2 | Added `SubAgentAttestation` definition and `sub_agent_chain` in result attestation claims |
| 0.1.2 | Added `sub_agent_policy` to contract consumer for multi-model composition controls |
| 0.1.2 | Added `NumericPrecisionPolicy` and `numeric_precision_policy` to contract result policy |
| 0.1.2 | Added `sub_agent_chain_declaration` to attestation `must_include` options |
| 0.1.3 | Added canonical serialization requirement (RFC 8785) for all hash computations (§2.5.1) |
| 0.1.3 | Added cryptographic requirements: signature algorithms, input format, encoding (§3.3) |
| 0.1.3 | Added revocation propagation mechanism with bounded delay (§2.3.1) |
| 0.1.3 | Added session lifecycle states and recovery semantics (§5.4) |
| 0.1.3 | Extended `numeric_precision_policy` scope to ALL numeric fields (§4.10) |
| 0.1.3 | Added progressive adoption path with implementation guides (§6.2) |
| 0.1.3 | Added wire protocol specification (OpenAPI 3.1) — `spec/dssp-api-v0.1.yaml` |
| 0.1.3 | Added interoperability test vectors — `reference/test-vectors/` |

## 10. References

- [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119) — Key words for RFCs
- [RFC 4648](https://www.rfc-editor.org/rfc/rfc4648) — Base16, Base32, Base64 encodings (§5: Base64url)
- [RFC 7517](https://www.rfc-editor.org/rfc/rfc7517) — JSON Web Key (JWK) format
- [RFC 8785](https://www.rfc-editor.org/rfc/rfc8785) — JSON Canonicalization Scheme (JCS)
- [JSON Schema Draft 2020-12](https://json-schema.org/draft/2020-12/schema)
- [W3C Verifiable Credentials](https://www.w3.org/TR/vc-data-model/) — Attestation model reference
- [NIST SP 800-233](https://csrc.nist.gov/) — Confidential computing guidelines
- [TCG DICE](https://trustedcomputinggroup.org/work-groups/dice-architectures/) — Device attestation
- [Open Data Format](https://opendataformat.github.io/specification.html) — Metadata standardization reference
- [OASIS CMIS](http://docs.oasis-open.org/cmis/) — Content management interoperability
- [Microsoft Presidio](https://microsoft.github.io/presidio/) — PII detection and anonymization (reference NER scanner)
- [OpenDP](https://opendp.org/) — Differential privacy framework (reference for privacy budget)
- [OpenAPI 3.1](https://spec.openapis.org/oas/v3.1.0) — API specification format for wire protocol

## Appendix A: Example Flow

See `examples/bank-statement-extraction/` for a complete example of:

1. A manifest describing 3 documents for an annual audit engagement
2. A processing contract granting DocuVerify access to bank statements
   (with AI agent restrictions, result scanning, document sanitization,
   privacy budget, and gateway isolation configured)
3. A result envelope with extracted data, attestation proof, PII report,
   result scan verdicts, and end-of-session attestation
4. An audit trail showing the complete chain of events (including sanitization,
   result scanning, and end-of-session attestation events)

## Appendix B: JSON Schemas

- `schemas/common.schema.json` — Shared types and definitions (including AgentType, ResultScanVerdict, PrivacyBudget, GatewayVisibility, SubAgentAttestation, NumericPrecisionPolicy)
- `schemas/manifest.schema.json` — Layer 1: Document Manifest
- `schemas/contract.schema.json` — Layer 2: Processing Contract
- `schemas/result.schema.json` — Layer 3: Result Envelope
- `schemas/audit-event.schema.json` — Layer 4: Audit Ledger
- `schemas/storage-binding.schema.json` — Layer 0: Storage Binding Interface

## Appendix C: Wire Protocol

The DSP wire protocol is defined in `spec/dssp-api-v0.1.yaml` (OpenAPI 3.1). It
specifies all HTTP endpoints, request/response schemas, authentication, error
handling, and version negotiation for DSP implementations.

Key endpoints:
- `POST /v0.1/manifests` — Create a document manifest
- `POST /v0.1/contracts` — Create a processing contract
- `POST /v0.1/sessions` — Start a processing session
- `POST /v0.1/sessions/{id}/complete` — Submit result and end session
- `GET /v0.1/audit/events` — Read the audit chain
- `GET /v0.1/.well-known/dssp-configuration` — Discovery and version negotiation

## Appendix D: Reference Implementations

- `reference/gateway/` — Reference DSP gateway (Go). Implements the full wire
  protocol with in-memory storage, contract enforcement, audit chain management,
  and RFC 8785 canonical JSON.
- `reference/storage-adapters/minio/` — MinIO storage adapter (Go). Maps DSP
  storage operations to MinIO S3-compatible API.
- `reference/scanner/` — Reference result scanner (Python). Implements regex,
  NER (Presidio), statistical (Benford's law), and LLM output filter scanners.
- `reference/conformance/` — Conformance test suite (Python/pytest). Tests
  behavior across all four conformance levels.
- `reference/sandbox/` — Docker Compose demo. Full working DSP environment
  with gateway, MinIO, scanner, demo agent, and audit viewer.

## Appendix E: Test Vectors

Interoperability test vectors are in `reference/test-vectors/`:

- `canonical-json/` — RFC 8785 canonical JSON serialization test cases
- `hash-computation/` — SHA-256 hash computation over canonical JSON
- `merkle-chain/` — Three-event Merkle chain with computed hashes
- `pii-redaction/` — mask_last_4, hash_sha256, and suppress redaction methods
- `numeric-precision/` — Rounding, banker's rounding, significant digits
- `sub-agent-chain/` — Valid and invalid pipeline configurations

Each vector file contains `input`, `expected_output`, and `description` fields
for automated verification.

## Appendix F: Agent Type Decision Tree

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
