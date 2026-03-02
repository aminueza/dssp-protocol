"""DSP Reference Implementation — Setup

Initializes the demo environment:
1. Creates a bucket in MinIO (document owner's storage)
2. Uploads sample bank statement documents
3. Computes document hashes for the manifest
4. Registers a manifest with the gateway
5. Registers a processing contract with the gateway
"""

import hashlib
import json
import os
import sys
import time

import httpx
from minio import Minio

MINIO_ENDPOINT = os.environ.get("MINIO_ENDPOINT", "storage:9000")
MINIO_ACCESS_KEY = os.environ.get("MINIO_ACCESS_KEY", "dsp-owner")
MINIO_SECRET_KEY = os.environ.get("MINIO_SECRET_KEY", "dsp-owner-secret-key")
GATEWAY_URL = os.environ.get("GATEWAY_URL", "http://gateway:8080")

BUCKET = "audit-engagement-2026-q1"
SAMPLE_DIR = "/app/sample-data"


def wait_for_service(url: str, name: str, max_retries: int = 30) -> None:
    """Wait for a service to become healthy."""
    for i in range(max_retries):
        try:
            r = httpx.get(f"{url}/health", timeout=3)
            if r.status_code == 200:
                print(f"  {name} is ready")
                return
        except Exception:
            pass
        time.sleep(1)
        if i % 5 == 4:
            print(f"  Waiting for {name}... ({i + 1}/{max_retries})")
    print(f"  ERROR: {name} not ready after {max_retries}s", file=sys.stderr)
    sys.exit(1)


def sha256_file(path: str) -> str:
    """Compute SHA-256 hash of a file."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def main() -> None:
    print("=" * 60)
    print("DSP Reference — Setup")
    print("=" * 60)

    # ── Step 1: Connect to MinIO ────────────────────────────
    print("\n[1/5] Connecting to MinIO...")
    client = Minio(
        MINIO_ENDPOINT,
        access_key=MINIO_ACCESS_KEY,
        secret_key=MINIO_SECRET_KEY,
        secure=False,
    )

    if not client.bucket_exists(BUCKET):
        client.make_bucket(BUCKET)
        print(f"  Created bucket: {BUCKET}")
    else:
        print(f"  Bucket exists: {BUCKET}")

    # ── Step 2: Upload sample documents ─────────────────────
    print("\n[2/5] Uploading sample documents...")
    documents = []
    for filename in sorted(os.listdir(SAMPLE_DIR)):
        filepath = os.path.join(SAMPLE_DIR, filename)
        if not os.path.isfile(filepath):
            continue

        object_name = f"statements/2025-12/{filename}"
        file_hash = sha256_file(filepath)
        file_size = os.path.getsize(filepath)

        client.fput_object(BUCKET, object_name, filepath)
        print(f"  Uploaded: {object_name} ({file_size} bytes)")

        # Determine bank name from filename
        bank = "Chase Bank" if "chase" in filename.lower() else "ING Bank N.V."

        documents.append({
            "document_id": f"doc-{hashlib.sha256(filename.encode()).hexdigest()[:16]}",
            "classification": "bank_statement",
            "sensitivity": "pii-high",
            "format": "text/plain",
            "storage_ref": {
                "type": "s3",
                "bucket": BUCKET,
                "key": object_name,
                "endpoint": MINIO_ENDPOINT,
            },
            "hash": {
                "algorithm": "sha-256",
                "value": file_hash,
            },
            "metadata": {
                "filename": filename,
                "document_type": "bank_statement",
                "institution": bank,
                "period": "2025-12",
                "currency": "USD" if "chase" in filename.lower() else "EUR",
            },
            "size_bytes": file_size,
            "mime_type": "text/plain",
        })

    # ── Step 3: Build and register manifest ─────────────────
    print("\n[3/5] Registering manifest with gateway...")
    manifest = {
        "$schema": "https://dsp.dev/schema/manifest/v0.1",
        "dsp_version": "0.1",
        "manifest_id": "mn-demo-bank-statements",
        "owner": {
            "org_id": "owner-acme-audit-corp",
            "org_name": "Acme Audit Corporation",
            "jurisdiction": "EU",
            "contact": "dsp-admin@acme-audit.example.com",
        },
        "engagement": {
            "engagement_id": "engagement-2026-q1-annual-audit",
            "description": "Annual financial audit — Q1 2026 bank statement review",
        },
        "documents": documents,
        "access_control": {
            "auth_method": "dsp_session_token",
            "token_endpoint": f"{GATEWAY_URL}/sessions",
            "max_concurrent_sessions": 1,
            "require_attestation": True,
        },
        "created_at": "2026-02-27T10:00:00Z",
        "expires_at": "2026-06-30T23:59:59Z",
    }

    r = httpx.post(f"{GATEWAY_URL}/v0.1/manifests", json=manifest, timeout=10)
    r.raise_for_status()
    print(f"  Manifest registered: {manifest['manifest_id']}")
    print(f"  Documents: {len(documents)}")

    # ── Step 4: Build and register contract ─────────────────
    print("\n[4/5] Registering contract with gateway...")
    contract = {
        "$schema": "https://dsp.dev/schema/contract/v0.1",
        "dsp_version": "0.1",
        "contract_id": "ct-demo-bank-extraction",
        "manifest_id": manifest["manifest_id"],
        "owner": manifest["owner"],
        "consumer": {
            "org_id": "consumer-docuverify-bv",
            "org_name": "DocuVerify B.V.",
            "agent_id": "docuverify-extractor-v4",
            "agent_versions_allowed": [">=4.0.0", "<5.0.0"],
            "agent_type": "ml_structured",
            "sub_agent_policy": {
                "allowed": True,
                "max_pipeline_steps": 4,
                "allowed_purposes": [
                    "ocr", "layout_detection",
                    "table_extraction", "key_value_extraction",
                    "validation",
                ],
                "require_sub_agent_hashes": True,
                "cross_enclave_allowed": False,
                "llm_sub_agent_allowed": False,
            },
        },
        "permissions": {
            "operations": ["read", "extract_structured", "extract_table"],
            "max_session_duration_seconds": 3600,
            "max_sessions_total": 10,
            "document_scope": [d["document_id"] for d in documents],
        },
        "restrictions": {
            "network_policy": {
                "egress": "allow_listed",
                "allowed_destinations": [
                    {"host": MINIO_ENDPOINT.split(":")[0],
                     "port": int(MINIO_ENDPOINT.split(":")[1]),
                     "purpose": "document_storage"},
                    {"host": "gateway",
                     "port": 8080,
                     "purpose": "dsp_gateway"},
                ],
            },
            "result_policy": {
                "raw_content_allowed": False,
                "summary_allowed": True,
                "extracted_fields_allowed": True,
                "extracted_tables_allowed": True,
                "free_text_fields_policy": "scan_and_redact",
                "max_string_field_length": 200,
                "numeric_precision_policy": {
                    "max_decimal_places": 2,
                    "max_significant_digits": 12,
                    "enforce_standard_rounding": True,
                    "detect_entropy_anomaly": True,
                    "currency_fields_integer_cents": False,
                },
            },
            "result_scanning": {
                "enabled": True,
                "scanners_required": ["regex_pattern", "ner_entity"],
                "fail_action": "redact_and_flag",
                "min_confidence_threshold": 0.7,
            },
            "document_sanitization_policy": {
                "pre_processing_sanitization": True,
                "strip_metadata": True,
                "strip_embedded_objects": True,
                "allowed_content_types": ["text/plain"],
                "max_document_size_bytes": 10485760,
            },
            "privacy_budget": {
                "k_anonymity_minimum": 5,
                "max_unique_identifiers_in_result": 0,
                "differential_privacy": {
                    "enabled": False,
                },
            },
        },
        "attestation_requirements": {
            "enclave_types": ["sev-snp", "sgx", "nitro", "tdx", "sandbox"],
            "min_tcb_version": "2024.01",
            "must_include": [
                "agent_binary_hash", "input_document_hashes",
                "network_connection_log", "output_result_hash",
                "result_scan_verdict", "sanitizer_execution_proof",
                "end_of_session_measurement", "sub_agent_chain_declaration",
            ],
            "runtime_verification": {
                "end_of_session_attestation_required": True,
                "sidecar_verifier_required": False,
            },
        },
        "audit": {
            "immutable_log_required": True,
            "hash_chain_algorithm": "sha-256",
            "retention_days": 2555,
        },
        "created_at": "2026-02-27T10:00:00Z",
        "expires_at": "2026-06-30T23:59:59Z",
        "status": "active",
    }

    r = httpx.post(f"{GATEWAY_URL}/v0.1/contracts", json=contract, timeout=10)
    r.raise_for_status()
    print(f"  Contract registered: {contract['contract_id']}")
    print(f"  Consumer: {contract['consumer']['org_name']}")
    print(f"  Agent type: {contract['consumer']['agent_type']}")

    # ── Step 5: Store tokens for agent ──────────────────────
    print("\n[5/5] Writing agent config...")
    agent_config = {
        "gateway_url": GATEWAY_URL,
        "minio_endpoint": MINIO_ENDPOINT,
        "contract_id": contract["contract_id"],
        "manifest_id": manifest["manifest_id"],
    }
    with open("/app/agent-config.json", "w") as f:
        json.dump(agent_config, f, indent=2)
    print("  Agent config written")

    print("\n" + "=" * 60)
    print("Setup complete. Agent can now process documents.")
    print("=" * 60)


if __name__ == "__main__":
    main()

