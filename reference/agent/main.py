"""DSP Reference Implementation — Enclave Agent

Document processing agent with pluggable enclave attestation:
  1. Boots and generates attestation (simulated / Gramine / Nitro)
  2. Starts a session with the DSP Gateway
  3. Downloads documents from MinIO via scoped token
  4. Extracts structured data (regex-based, no ML needed)
  5. Detects and redacts PII per contract rules
  6. Runs result scanning (regex patterns + simulated NER)
  7. Produces a DSP result envelope with full attestation
  8. Submits the result to the gateway

Enclave backends (set ENCLAVE_MODE env var):
  simulated : Fake attestation for dev/CI (default)
  gramine   : Gramine gramine-direct or gramine-sgx
  nitro     : AWS Nitro Enclaves (requires EC2 Nitro instance)
"""

import hashlib
import json
import os
import re
import sys
import time
import uuid
from datetime import datetime, timezone

import httpx
from minio import Minio

from attestation import create_attestor

GATEWAY_URL = os.environ.get("GATEWAY_URL", "http://gateway:8080")
MINIO_ENDPOINT = os.environ.get("MINIO_ENDPOINT", "storage:9000")

# Agent identity
AGENT_ID = "docuverify-extractor-v4"
AGENT_VERSION = "4.2.1"


def now_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def wait_for_gateway(max_retries: int = 60) -> None:
    for i in range(max_retries):
        try:
            r = httpx.get(f"{GATEWAY_URL}/health", timeout=3)
            if r.status_code == 200:
                print("  Gateway is ready")
                return
        except Exception:
            pass
        time.sleep(1)
        if i % 10 == 9:
            print(f"  Waiting for gateway... ({i + 1}/{max_retries})")
    print("  ERROR: Gateway not ready", file=sys.stderr)
    sys.exit(1)


# ── Document Parsing ────────────────────────────────────────

def parse_bank_statement(text: str) -> dict:
    """Parse a bank statement text file into structured data."""
    fields: dict = {}
    transactions: list[dict] = []

    # Extract header fields
    patterns = {
        "account_holder": r"Account Holder:\s*(.+)",
        "account_number": r"Account Number:\s*(.+)",
        "iban": r"IBAN:\s*(.+)",
        "routing_number": r"Routing Number:\s*(.+)",
        "bic": r"BIC:\s*(.+)",
        "account_type": r"Account Type:\s*(.+)",
        "currency": r"Currency:\s*(\w+)",
        "opening_balance": r"Opening Balance:\s*([\d.]+)",
        "closing_balance": r"Closing Balance:\s*([\d.]+)",
        "total_credits": r"Total Credits:\s*([\d.]+)",
        "total_debits": r"Total Debits:\s*([\d.]+)",
    }
    for key, pattern in patterns.items():
        m = re.search(pattern, text)
        if m:
            fields[key] = m.group(1).strip()

    # Extract period
    m = re.search(r"Statement Period:\s*(.+)", text)
    if m:
        fields["statement_period"] = m.group(1).strip()

    # Extract bank name from header
    m = re.search(r"^([\w\s.]+)\s*-\s*(?:ACCOUNT STATEMENT|REKENINGOVERZICHT)", text, re.MULTILINE)
    if m:
        fields["bank_name"] = m.group(1).strip()

    # Extract transactions (pipe-delimited: Date|Description|Amount|Balance)
    in_transactions = False
    for line in text.split("\n"):
        if line.strip() == "TRANSACTIONS":
            in_transactions = True
            continue
        if in_transactions and line.strip().startswith("Date|"):
            continue  # skip header
        if in_transactions and "|" in line:
            parts = line.strip().split("|")
            if len(parts) == 4:
                try:
                    transactions.append({
                        "date": parts[0].strip(),
                        "description": parts[1].strip(),
                        "amount": float(parts[2].strip()),
                        "balance": float(parts[3].strip()),
                    })
                except ValueError:
                    pass

    return {"fields": fields, "transactions": transactions}


# ── PII Detection ───────────────────────────────────────────

# Patterns that indicate PII
PII_PATTERNS = {
    "iban": r"\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7,25}\b",
    "account_number": r"\b\d{10,20}\b",
    "routing_number": r"\b0\d{8}\b",
    "person_name": r"\b(?:from|to|Holder:)\s+([A-Z][a-z]+(?: (?:van |de |den |M\. )?[A-Z][a-z.]+)+)",
    "email": r"\b[\w.-]+@[\w.-]+\.\w+\b",
}

# Fields that are inherently PII
PII_FIELDS = {"account_holder", "account_number", "iban", "routing_number", "bic"}


def detect_pii_in_text(text: str) -> list[dict]:
    """Find PII patterns in free text."""
    findings: list[dict] = []
    for pii_type, pattern in PII_PATTERNS.items():
        for m in re.finditer(pattern, text):
            findings.append({
                "type": pii_type,
                "value": m.group(0),
                "start": m.start(),
                "end": m.end(),
            })
    return findings


def redact_value(value: str, method: str) -> str:
    """Redact a PII value using the specified method."""
    if method == "mask_last_4":
        if len(value) > 4:
            return "*" * (len(value) - 4) + value[-4:]
        return "*" * len(value)
    elif method == "hash_sha256":
        return "SHA256:" + hashlib.sha256(value.encode()).hexdigest()[:16]
    elif method == "suppress":
        return "[REDACTED]"
    elif method == "generalize":
        # For names, keep first letter only
        parts = value.split()
        return " ".join(p[0] + "." for p in parts if p)
    return value


# ── Result Scanning ─────────────────────────────────────────

def scan_result_for_pii(result_data: dict) -> dict:
    """Scan the result envelope for residual PII. Simulates regex + NER scanners."""
    verdicts: list[dict] = []
    total_findings = 0
    fields_modified = 0

    # Regex scanner
    regex_findings: list[str] = []
    result_text = json.dumps(result_data.get("extractions", []))
    for pii_type, pattern in PII_PATTERNS.items():
        matches = re.findall(pattern, result_text)
        if matches:
            regex_findings.extend(matches)
    total_findings += len(regex_findings)

    verdicts.append({
        "scanner_type": "regex_pattern",
        "scanner_version": "1.0.0",
        "verdict": "pass" if len(regex_findings) == 0 else "flag",
        "findings_count": len(regex_findings),
        "details": f"Checked {len(PII_PATTERNS)} patterns"
            + (f", found: {', '.join(regex_findings[:3])}" if regex_findings else ""),
    })

    # Simulated NER scanner (in production, uses spaCy/transformers)
    ner_findings = 0
    ner_entities: list[str] = []
    for ext in result_data.get("extractions", []):
        for key, val in ext.get("fields", {}).items():
            if isinstance(val, str) and re.search(r"[A-Z][a-z]+ [A-Z][a-z]+", val):
                ner_findings += 1
                ner_entities.append(f"PERSON({val[:20]})")
    total_findings += ner_findings

    verdicts.append({
        "scanner_type": "ner_entity",
        "scanner_version": "1.0.0-simulated",
        "verdict": "pass" if ner_findings == 0 else "flag",
        "findings_count": ner_findings,
        "details": f"NER scan (simulated)"
            + (f", found: {', '.join(ner_entities[:3])}" if ner_entities else ""),
    })

    return {
        "performed": True,
        "overall_verdict": "pass" if total_findings == 0 else "pass_with_modifications",
        "verdicts": verdicts,
        "total_findings": total_findings,
        "fields_modified_by_scan": fields_modified,
        "scan_duration_ms": 450,
    }


# ── Extraction Pipeline ────────────────────────────────────

def process_document(
    doc_meta: dict,
    doc_content: bytes,
    contract: dict,
) -> dict:
    """Process a single document: parse → extract → redact → return extraction."""
    text = doc_content.decode("utf-8")
    parsed = parse_bank_statement(text)

    # Build extraction with PII redaction
    fields = {}
    pii_encountered: list[str] = []
    pii_redacted: list[str] = []
    redaction_methods: set[str] = set()

    for key, value in parsed["fields"].items():
        if key in PII_FIELDS:
            pii_encountered.append(key)
            if key == "account_number":
                fields[key] = redact_value(value, "mask_last_4")
                pii_redacted.append(key)
                redaction_methods.add("mask_last_4")
            elif key == "account_holder":
                fields[key] = redact_value(value, "generalize")
                pii_redacted.append(key)
                redaction_methods.add("generalize")
            elif key in ("iban", "routing_number", "bic"):
                fields[key] = redact_value(value, "hash_sha256")
                pii_redacted.append(key)
                redaction_methods.add("hash_sha256")
            else:
                fields[key] = redact_value(value, "suppress")
                pii_redacted.append(key)
                redaction_methods.add("suppress")
        else:
            fields[key] = value

    # Process transactions — redact descriptions containing names
    table_rows = []
    for tx in parsed["transactions"]:
        desc = tx["description"]
        # Check for person names in description
        name_match = re.search(r"(?:from|to)\s+([A-Z][a-z]+(?: (?:van |de |den |M\. )?[A-Z][a-z.]+)+)", desc)
        if name_match:
            pii_encountered.append("transaction_description")
            pii_encountered.append("counterparty_name")
            redacted_name = redact_value(name_match.group(1), "generalize")
            desc = desc[:name_match.start(1)] + redacted_name + desc[name_match.end(1):]
            pii_redacted.append("transaction_description")
            pii_redacted.append("counterparty_name")
            redaction_methods.add("generalize")

        table_rows.append({
            "date": tx["date"],
            "description": desc,
            "amount": round(tx["amount"], 2),
            "balance": round(tx["balance"], 2),
        })

    extraction = {
        "document_id": doc_meta["document_id"],
        "document_hash": doc_meta.get("hash", {}),
        "extraction_type": "bank_statement",
        "fields": fields,
        "tables": [{
            "table_id": "transactions",
            "headers": ["date", "description", "amount", "balance"],
            "column_definitions": [
                {"name": "date", "type": "date", "pii_bearing": False},
                {"name": "description", "type": "string", "pii_bearing": True},
                {"name": "amount", "type": "decimal", "pii_bearing": False},
                {"name": "balance", "type": "decimal", "pii_bearing": False},
            ],
            "rows": table_rows,
            "row_count": len(table_rows),
        }],
    }

    return {
        "extraction": extraction,
        "pii_encountered": list(set(pii_encountered)),
        "pii_redacted": list(set(pii_redacted)),
        "redaction_methods": list(redaction_methods),
    }


# ── Main Flow ───────────────────────────────────────────────

def main() -> None:
    print("=" * 60)
    print("DSP Reference — Enclave Agent")
    print("=" * 60)

    # ── Step 0: Initialize attestation backend ──────────────
    attestor = create_attestor(agent_id=AGENT_ID, agent_version=AGENT_VERSION)
    backend_name = attestor.get_backend_name()
    enclave_type = attestor.get_enclave_type()
    print(f"\n  Attestation backend: {backend_name}")
    print(f"  Enclave type: {enclave_type}")

    # ── Step 1: Wait and fetch contract ─────────────────────
    print("\n[1/7] Connecting to gateway...")
    wait_for_gateway()

    # Discover configuration and fetch contract + manifest
    api = f"{GATEWAY_URL}/v0.1"

    # List contracts and manifests from the Go gateway
    r = httpx.get(f"{api}/contracts", timeout=10)
    contracts_resp = r.json()
    contracts = contracts_resp.get("items", [])
    if not contracts:
        print("  ERROR: No contracts registered", file=sys.stderr)
        sys.exit(1)

    contract = contracts[0]
    contract_id = contract["contract_id"]

    r = httpx.get(f"{api}/manifests", timeout=10)
    manifests_resp = r.json()
    manifests = manifests_resp.get("items", [])
    if not manifests:
        print("  ERROR: No manifests registered", file=sys.stderr)
        sys.exit(1)

    manifest = manifests[0]
    manifest_id = manifest["manifest_id"]

    print(f"  Contract: {contract_id}")
    print(f"  Manifest: {manifest_id}")
    print(f"  Documents: {len(manifest.get('documents', []))}")

    # ── Step 2: Generate attestation ────────────────────────
    nonce = f"{contract_id}:{manifest_id}:{now_utc()}".encode()
    report = attestor.generate_report(user_data=nonce)
    start_measurement = report.measurement

    print(f"\n[2/7] Generating enclave attestation ({backend_name})...")
    print(f"  Enclave type:  {report.enclave_type}")
    print(f"  Backend:       {report.backend}")
    print(f"  Agent:         {AGENT_ID} v{AGENT_VERSION}")
    print(f"  Measurement:   {report.measurement[:32]}...")
    print(f"  Signed by:     {report.signed_by}")
    if report.raw_quote:
        print(f"  Raw quote:     {len(report.raw_quote)} chars (base64)")

    attestation = report.to_dict()
    attestation["agent_id"] = AGENT_ID
    attestation["agent_version"] = AGENT_VERSION

    # ── Step 3: Start session ───────────────────────────────
    print("\n[3/7] Starting processing session...")
    session_req = {
        "contract_id": contract_id,
        "manifest_id": manifest_id,
        "attestation": {
            "enclave_type": attestation.get("enclave_type", enclave_type),
            "measurement": attestation.get("measurement", ""),
            "agent_hash": attestation.get("agent_hash"),
            "timestamp": attestation.get("timestamp", now_utc()),
            "signature": attestation.get("signature", ""),
        },
        "agent_org_id": contract.get("consumer", {}).get("org_id", ""),
        "agent_id": AGENT_ID,
    }

    r = httpx.post(f"{api}/sessions", json=session_req, timeout=10)
    if r.status_code not in (200, 201):
        print(f"  ERROR: Session rejected ({r.status_code}): {r.text}", file=sys.stderr)
        sys.exit(1)

    session = r.json()
    session_id = session["session_id"]
    token = session["token"]
    manifest_data = session.get("manifest", manifest)
    print(f"  Session: {session_id}")
    print(f"  Token expires: {token['expires_at']}")

    # ── Step 4: Download documents from MinIO ───────────────
    print("\n[4/7] Downloading documents from storage...")
    # In production, credentials come from a storage grant or the scoped token.
    # For the reference impl, we use the same credentials as setup.
    minio_access = os.environ.get("MINIO_ACCESS_KEY", "dsp-owner")
    minio_secret = os.environ.get("MINIO_SECRET_KEY", "dsp-owner-secret-key")
    minio_client = Minio(
        MINIO_ENDPOINT,
        access_key=minio_access,
        secret_key=minio_secret,
        secure=False,
    )

    documents: list[tuple[dict, bytes]] = []
    input_hashes: list[dict] = []

    for doc in manifest_data.get("documents", []):
        ref = doc["storage_ref"]
        bucket = ref["bucket"]
        key = ref["key"]

        print(f"  Downloading: {key}")
        response = minio_client.get_object(bucket, key)
        content = response.read()
        response.close()
        response.release_conn()

        doc_hash = sha256_bytes(content)
        input_hashes.append({
            "document_id": doc["document_id"],
            "hash": {"algorithm": "sha-256", "value": doc_hash},
            "size_bytes": len(content),
        })
        documents.append((doc, content))

    print(f"  Downloaded {len(documents)} documents")

    # ── Step 5: Process documents ───────────────────────────
    print("\n[5/7] Processing documents...")
    extractions = []
    all_pii_encountered: set[str] = set()
    all_pii_redacted: set[str] = set()
    all_methods: set[str] = set()

    for doc_meta, doc_content in documents:
        institution = doc_meta.get("metadata", {}).get("institution", "Unknown")
        print(f"  Processing: {institution}")

        result = process_document(doc_meta, doc_content, contract)
        extractions.append(result["extraction"])
        all_pii_encountered.update(result["pii_encountered"])
        all_pii_redacted.update(result["pii_redacted"])
        all_methods.update(result["redaction_methods"])

        print(f"    Fields: {len(result['extraction']['fields'])}")
        print(f"    Transactions: {result['extraction']['tables'][0]['row_count']}")
        print(f"    PII found: {len(result['pii_encountered'])}")

    # ── Step 6: Scan results ────────────────────────────────
    print("\n[6/7] Scanning result for residual PII...")
    result_data_for_scan = {"extractions": extractions}
    scan_report = scan_result_for_pii(result_data_for_scan)

    for v in scan_report["verdicts"]:
        status = "✅" if v["verdict"] == "pass" else "⚠️"
        print(f"  {status} {v['scanner_type']}: {v['verdict']} ({v['findings_count']} findings)")

    # ── Step 7: Build and submit result envelope ────────────
    print("\n[7/7] Building result envelope...")

    # Sub-agent chain (this demo uses a 3-step pipeline)
    sub_agent_chain = [
        {
            "step_index": 0,
            "agent_type": "deterministic",
            "agent_id": "text-parser-1.0",
            "agent_hash": {"algorithm": "sha-256", "value": sha256_bytes(b"text-parser-1.0")},
            "agent_version": "1.0.0",
            "purpose": "ocr",
            "input_type": "raw_document",
            "output_type": "extracted_text",
            "enclave_shared": True,
            "network_access": False,
        },
        {
            "step_index": 1,
            "agent_type": "ml_structured",
            "agent_id": "layout-detector-2.1",
            "agent_hash": {"algorithm": "sha-256", "value": sha256_bytes(b"layout-detector-2.1")},
            "agent_version": "2.1.0",
            "purpose": "layout_detection",
            "input_type": "extracted_text",
            "output_type": "structured_layout",
            "enclave_shared": True,
            "network_access": False,
        },
        {
            "step_index": 2,
            "agent_type": "ml_structured",
            "agent_id": "table-extractor-3.0",
            "agent_hash": {"algorithm": "sha-256", "value": sha256_bytes(b"table-extractor-3.0")},
            "agent_version": "3.0.2",
            "purpose": "table_extraction",
            "input_type": "structured_layout",
            "output_type": "structured_data",
            "enclave_shared": True,
            "network_access": False,
        },
    ]

    # Generate result attestation with claims
    result_report = attestor.generate_report(
        user_data=json.dumps(extractions, sort_keys=True).encode()[:256]
    )
    result_attestation = result_report.to_dict()
    result_attestation["claims"] = {
        "input_document_hashes": input_hashes,
        "network_destinations": [
            f"{MINIO_ENDPOINT.split(':')[0]}:{MINIO_ENDPOINT.split(':')[1]}",
            "gateway:8080",
        ],
        "output_result_hash": {
            "algorithm": "sha-256",
            "value": sha256_bytes(json.dumps(extractions, sort_keys=True).encode()),
        },
        "sub_agent_chain": sub_agent_chain,
    }

    # Generate end-of-session attestation proving enclave wasn't tampered with
    eos_attestation = attestor.end_of_session_report(start_measurement)

    result_envelope = {
        "$schema": "https://dsp.dev/schema/result/v0.1",
        "dsp_version": "0.1",
        "result_id": f"rs-{uuid.uuid4().hex[:16]}",
        "contract_id": contract_id,
        "session_id": session_id,
        "produced_at": now_utc(),
        "attestation": result_attestation,
        "extractions": extractions,
        "result_scan": scan_report,
        "pii_report": {
            "fields_encountered": sorted(all_pii_encountered),
            "fields_redacted": sorted(all_pii_redacted),
            "redaction_methods_used": sorted(all_methods),
            "raw_content_included": False,
            "compliance_status": "compliant",
        },
        "end_of_session_attestation": eos_attestation,
    }

    # Submit to gateway
    print("  Submitting result to gateway...")
    r = httpx.post(
        f"{api}/sessions/{session_id}/result",
        json=result_envelope,
        timeout=30,
    )

    if r.status_code not in (200, 201):
        print(f"  ERROR: Result rejected ({r.status_code}): {r.text}", file=sys.stderr)
        sys.exit(1)

    response = r.json()
    validation = response.get("validation", {})

    print(f"\n{'=' * 60}")
    print(f"Processing complete!")
    print(f"{'=' * 60}")
    print(f"  Result ID:      {result_envelope['result_id']}")
    print(f"  Documents:      {len(extractions)}")
    print(f"  PII encountered:{len(all_pii_encountered)}")
    print(f"  PII redacted:   {len(all_pii_redacted)}")
    print(f"  Scan verdict:   {scan_report['overall_verdict']}")
    print(f"  Validation:     {'PASSED ✅' if validation.get('valid') else 'ISSUES ⚠️'}")
    if validation.get("issues"):
        for issue in validation["issues"]:
            print(f"    ❌ {issue}")
    if validation.get("warnings"):
        for warn in validation["warnings"]:
            print(f"    ⚠️  {warn}")
    print(f"\n  Dashboard: http://localhost:8080")
    print(f"{'=' * 60}")


if __name__ == "__main__":
    main()

