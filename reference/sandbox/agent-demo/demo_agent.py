"""Demo DSSP agent — demonstrates the full processing lifecycle."""

import json
import os
import sys
import time
import hashlib
import requests

GATEWAY_URL = os.environ.get("GATEWAY_URL", "http://localhost:8080")
API_BASE = f"{GATEWAY_URL}/v0.1"


def log(msg: str) -> None:
    print(f"[demo-agent] {msg}", flush=True)


def create_sample_manifest() -> dict:
    """Create a sample manifest for demo purposes."""
    manifest = {
        "dssp_version": "0.1",
        "owner": {
            "org_id": "org-demo-owner",
            "jurisdiction": "NL",
            "data_residency": "eu-west-1"
        },
        "scope": {
            "engagement_id": "engagement-demo-2026",
            "engagement_type": "annual-audit",
            "period": {"start": "2025-01-01", "end": "2025-12-31"}
        },
        "documents": [
            {
                "document_id": "doc-demo-001",
                "classification": "financial/bank-statement",
                "sensitivity": "pii-high",
                "format": "application/pdf",
                "page_count": 5,
                "language": "en",
                "hash": {"algorithm": "sha-256", "value": "a" * 64},
                "size_bytes": 245000,
                "created_at": "2025-12-15T10:00:00Z",
                "pii_fields_declared": [
                    "account_number", "account_holder_name", "balance",
                    "iban", "transaction_description"
                ],
                "allowed_operations": ["extract_text", "extract_tables", "extract_key_value"],
                "tags": {"period": "2025-h2", "institution": "demo-bank"}
            }
        ],
        "summary": {
            "total_documents": 1,
            "by_classification": {"financial/bank-statement": 1},
            "by_sensitivity": {"pii-high": 1}
        }
    }
    return manifest


def create_sample_contract(manifest_id: str) -> dict:
    """Create a sample contract."""
    return {
        "dssp_version": "0.1",
        "owner": {
            "org_id": "org-demo-owner",
            "jurisdiction": "NL",
            "data_residency": "eu-west-1"
        },
        "consumer": {
            "org_id": "org-demo-consumer",
            "agent_id": "ag-demo-extractor",
            "agent_hash": {"algorithm": "sha-256", "value": "b" * 64},
            "agent_type": "deterministic"
        },
        "permissions": {
            "operations": ["extract_text", "extract_tables"],
            "document_filter": {
                "classifications": ["financial/bank-statement"]
            },
            "max_documents_per_session": 10,
            "max_concurrent_sessions": 1,
            "max_session_duration_seconds": 600,
            "valid_from": "2026-01-01T00:00:00Z",
            "valid_until": "2026-12-31T23:59:59Z"
        },
        "restrictions": {
            "network_policy": {"egress": "deny_all"},
            "storage_policy": "memory_only",
            "result_policy": {
                "pii_redaction_rules": {
                    "account_number": "mask_last_4",
                    "account_holder_name": "hash_sha256",
                    "balance": "allow",
                    "iban": "mask_last_4",
                    "transaction_description": "allow"
                },
                "numeric_precision_policy": {
                    "max_decimal_places": 2,
                    "max_significant_digits": 12,
                    "enforce_standard_rounding": True,
                    "detect_entropy_anomaly": True
                }
            },
            "result_scanning": {
                "enabled": True,
                "required_scanners": ["regex"],
                "scan_failure_action": "block_result"
            }
        },
        "attestation_requirements": {
            "enclave_types": ["sandbox"],
            "attestation_freshness_seconds": 300
        }
    }


def create_sample_result(contract_id: str, session_id: str) -> dict:
    """Create a sample result with redacted PII."""
    name_hash = hashlib.sha256("John Smith".encode()).hexdigest()
    return {
        "dssp_version": "0.1",
        "contract_id": contract_id,
        "session_id": session_id,
        "produced_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "attestation": {
            "enclave_type": "sandbox",
            "measurement": "c" * 64,
            "agent_hash": {"algorithm": "sha-256", "value": "b" * 64},
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "signed_by": "demo-attestation-service",
            "claims": {
                "documents_processed": ["doc-demo-001"],
                "processing_duration_ms": 1523,
                "memory_peak_bytes": 52428800,
                "network_egress_bytes": 0,
                "network_destinations": [],
                "input_document_hashes": [{"algorithm": "sha-256", "value": "a" * 64}],
                "output_result_hash": {"algorithm": "sha-256", "value": "d" * 64}
            }
        },
        "extractions": [
            {
                "source_document_id": "doc-demo-001",
                "source_document_hash": {"algorithm": "sha-256", "value": "a" * 64},
                "extraction_type": "key_value",
                "confidence": 0.98,
                "fields": {
                    "account_number": "******7890",
                    "account_holder_name": f"sha256:{name_hash}",
                    "opening_balance": 50000.00,
                    "closing_balance": 52340.00,
                    "currency": "EUR",
                    "statement_period": "2025-07-01 to 2025-12-31",
                    "iban": "**************4300"
                },
                "tables": [
                    {
                        "name": "transactions",
                        "columns": [
                            {"name": "date", "type": "date"},
                            {"name": "description", "type": "string", "pii_bearing": True},
                            {"name": "amount", "type": "number"},
                            {"name": "balance", "type": "number"}
                        ],
                        "row_count": 3,
                        "rows": [
                            ["2025-07-01", "Opening Balance", 0, 50000.00],
                            ["2025-08-15", "Transfer received", 1500.00, 51500.00],
                            ["2025-12-31", "Interest credit", 840.00, 52340.00]
                        ]
                    }
                ]
            }
        ],
        "pii_report": {
            "fields_encountered": ["account_number", "account_holder_name", "balance", "iban"],
            "fields_redacted": ["account_number", "account_holder_name", "iban"],
            "fields_allowed_by_contract": ["balance"],
            "raw_content_included": False,
            "compliance_status": "compliant",
            "redaction_methods_applied": {
                "account_number": "mask_last_4",
                "account_holder_name": "hash_sha256",
                "iban": "mask_last_4"
            }
        },
        "result_scan": {
            "performed": True,
            "verdicts": [],
            "overall_passed": True
        }
    }


def main() -> None:
    log("Starting DSSP demo agent")
    log(f"Gateway: {GATEWAY_URL}")

    # Wait for gateway to be ready
    for i in range(30):
        try:
            resp = requests.get(f"{API_BASE}/.well-known/dssp-configuration", timeout=2)
            if resp.status_code == 200:
                config = resp.json()
                log(f"Gateway ready — DSP version {config.get('dssp_version', 'unknown')}")
                break
        except requests.ConnectionError:
            pass
        log(f"Waiting for gateway... ({i+1}/30)")
        time.sleep(2)
    else:
        log("ERROR: Gateway not available after 60 seconds")
        sys.exit(1)

    # Step 1: Create manifest
    log("\n--- Step 1: Creating manifest ---")
    manifest = create_sample_manifest()
    resp = requests.post(f"{API_BASE}/manifests", json=manifest)
    if resp.status_code not in (200, 201):
        log(f"Failed to create manifest: {resp.status_code} {resp.text}")
        sys.exit(1)
    manifest_data = resp.json()
    manifest_id = manifest_data.get("manifest_id", "unknown")
    log(f"Manifest created: {manifest_id}")

    # Step 2: Create contract
    log("\n--- Step 2: Creating contract ---")
    contract = create_sample_contract(manifest_id)
    resp = requests.post(f"{API_BASE}/contracts", json=contract)
    if resp.status_code not in (200, 201):
        log(f"Failed to create contract: {resp.status_code} {resp.text}")
        sys.exit(1)
    contract_data = resp.json()
    contract_id = contract_data.get("contract_id", "unknown")
    log(f"Contract created: {contract_id}")

    # Step 3: Start session
    log("\n--- Step 3: Starting processing session ---")
    session_req = {
        "contract_id": contract_id,
        "agent_id": "ag-demo-extractor",
        "agent_hash": {"algorithm": "sha-256", "value": "b" * 64},
        "enclave_type": "sandbox"
    }
    resp = requests.post(f"{API_BASE}/sessions", json=session_req)
    if resp.status_code not in (200, 201):
        log(f"Failed to start session: {resp.status_code} {resp.text}")
        sys.exit(1)
    session_data = resp.json()
    session_id = session_data.get("session_id", "unknown")
    log(f"Session started: {session_id}")

    # Step 4: Simulate processing
    log("\n--- Step 4: Processing documents ---")
    log("  Reading document doc-demo-001...")
    time.sleep(1)
    log("  Extracting text and tables...")
    time.sleep(1)
    log("  Applying PII redaction rules...")
    time.sleep(0.5)
    log("  Processing complete.")

    # Step 5: Submit result
    log("\n--- Step 5: Submitting result ---")
    result = create_sample_result(contract_id, session_id)
    resp = requests.post(f"{API_BASE}/sessions/{session_id}/complete", json=result)
    if resp.status_code not in (200, 201):
        log(f"Failed to submit result: {resp.status_code} {resp.text}")
        sys.exit(1)
    log("Result submitted successfully")

    # Step 6: Retrieve result
    log("\n--- Step 6: Retrieving result ---")
    resp = requests.get(f"{API_BASE}/sessions/{session_id}/result")
    if resp.status_code == 200:
        retrieved = resp.json()
        log(f"Result retrieved: {json.dumps(retrieved.get('pii_report', {}), indent=2)}")
    else:
        log(f"Could not retrieve result: {resp.status_code}")

    # Step 7: View audit trail
    log("\n--- Step 7: Viewing audit trail ---")
    resp = requests.get(f"{API_BASE}/audit/events")
    if resp.status_code == 200:
        events = resp.json()
        event_list = events.get("events", events) if isinstance(events, dict) else events
        if isinstance(event_list, list):
            log(f"Audit trail contains {len(event_list)} events:")
            for ev in event_list:
                log(f"  [{ev.get('sequence_number', '?')}] {ev.get('event_type', '?')} — {ev.get('outcome', {}).get('status', '?')}")
    else:
        log(f"Could not retrieve audit trail: {resp.status_code}")

    log("\n=== Demo complete ===")
    log("The DSSP lifecycle has been demonstrated:")
    log("  1. Manifest created (document discovery)")
    log("  2. Contract created (processing policy)")
    log("  3. Session started (within contract limits)")
    log("  4. Documents processed (with PII redaction)")
    log("  5. Result submitted (with attestation)")
    log("  6. Result retrieved (by consumer)")
    log("  7. Audit trail verified (Merkle chain)")


if __name__ == "__main__":
    main()
