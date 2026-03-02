"""DSSP Reference Implementation — Setup

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
MINIO_ACCESS_KEY = os.environ.get("MINIO_ACCESS_KEY", "dssp-owner")
MINIO_SECRET_KEY = os.environ.get("MINIO_SECRET_KEY", "dssp-owner-secret-key")
GATEWAY_URL = os.environ.get("GATEWAY_URL", "http://gateway:8080")

BUCKET = "audit-engagement-2026-q1"
SAMPLE_DIR = "/app/sample-data"


def wait_for_service(url: str, name: str, max_retries: int = 30) -> None:
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
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def main() -> None:
    print("=" * 60)
    print("DSSP Reference — Setup")
    print("=" * 60)

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

        # Document IDs must match schema pattern: ^[a-z]{2,4}-[a-f0-9]{8,64}$
        doc_id = f"doc-{hashlib.sha256(filename.encode()).hexdigest()[:16]}"

        documents.append(
            {
                "document_id": doc_id,
                "classification": "financial/bank-statement",
                "sensitivity": "pii-high",
                "format": "text/plain",
                "mime_type": "text/plain",
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
                "size_bytes": file_size,
                "metadata": {
                    "period": "2025-12",
                    "currency": "USD" if "chase" in filename.lower() else "EUR",
                },
            }
        )

    # Generate hex-based IDs conforming to the schema pattern
    manifest_id = f"mf-{hashlib.sha256(b'demo-bank-statements').hexdigest()[:16]}"
    contract_id = f"ct-{hashlib.sha256(b'demo-bank-extraction').hexdigest()[:16]}"

    print("\n[3/5] Registering manifest with gateway...")
    manifest = {
        "$schema": "https://dssp.dev/schema/manifest/v0.1",
        "dssp_version": "0.1",
        "manifest_id": manifest_id,
        "owner": {
            "org_id": "org-acme-audit-corp",
            "jurisdiction": "EU",
        },
        "scope": {
            "engagement_id": "engagement-2026-q1-annual-audit",
            "period": {
                "from": "2025-12-01",
                "to": "2025-12-31",
            },
            "tags": ["annual-audit", "bank-statements", "q1-2026"],
        },
        "documents": documents,
        "created_at": "2026-02-27T10:00:00Z",
        "expires_at": "2026-06-30T23:59:59Z",
    }

    r = httpx.post(f"{GATEWAY_URL}/v0.1/manifests", json=manifest, timeout=10)
    r.raise_for_status()
    print(f"  Manifest registered: {manifest_id}")
    print(f"  Documents: {len(documents)}")

    print("\n[4/5] Registering contract with gateway...")
    contract = {
        "$schema": "https://dssp.dev/schema/contract/v0.1",
        "dssp_version": "0.1",
        "contract_id": contract_id,
        "version": 1,
        "owner": {
            "org_id": "org-acme-audit-corp",
            "jurisdiction": "EU",
        },
        "consumer": {
            "org_id": "org-docuverify-bv",
            "agent_type": "ml_structured",
            "sub_agent_policy": {
                "allowed": True,
                "max_pipeline_steps": 4,
                "allowed_purposes": [
                    "ocr",
                    "layout_detection",
                    "table_extraction",
                    "key_value_extraction",
                    "validation",
                ],
                "require_sub_agent_hashes": True,
                "cross_enclave_allowed": False,
                "llm_sub_agent_allowed": False,
            },
        },
        "permissions": {
            "operations": ["extract_text", "extract_tables", "extract_key_value"],
            "max_session_duration_seconds": 3600,
            "max_concurrent_sessions": 1,
        },
        "restrictions": {
            "network_policy": {
                "egress": "allow_listed",
                "allowed_destinations": [
                    {
                        "host": MINIO_ENDPOINT.split(":")[0],
                        "port": int(MINIO_ENDPOINT.split(":")[1]),
                        "purpose": "document_storage",
                    },
                    {"host": "gateway", "port": 8080, "purpose": "dssp_gateway"},
                ],
            },
            "result_policy": {
                "pii_redaction_rules": {
                    "full_name": "hash_sha256",
                    "account_number": "mask_last_4",
                    "routing_number": "suppress",
                    "iban": "mask_last_4",
                    "address": "suppress",
                    "ssn": "suppress",
                    "tax_id": "suppress",
                },
                "numeric_precision_policy": {
                    "max_decimal_places": 2,
                    "max_significant_digits": 12,
                    "enforce_standard_rounding": True,
                    "detect_entropy_anomaly": True,
                },
            },
            "storage_policy": "memory_only",
            "result_scanning": {
                "enabled": True,
                "required_scanners": ["regex", "ner"],
                "scan_failure_action": "block_result",
            },
        },
        "attestation_requirements": {
            "enclave_types": ["sev-snp", "sgx", "nitro", "tdx", "sandbox"],
            "must_include": [
                "agent_binary_hash",
                "input_document_hashes",
                "network_connections_log",
                "output_result_hash",
                "result_scan_verdict",
                "end_of_session_measurement",
                "sub_agent_chain_declaration",
            ],
        },
        "created_at": "2026-02-27T10:00:00Z",
        "status": "active",
    }

    r = httpx.post(f"{GATEWAY_URL}/v0.1/contracts", json=contract, timeout=10)
    r.raise_for_status()
    print(f"  Contract registered: {contract_id}")
    print("  Consumer: org-docuverify-bv")
    print("  Agent type: ml_structured")

    print("\n[5/5] Writing agent config...")
    agent_config = {
        "gateway_url": GATEWAY_URL,
        "minio_endpoint": MINIO_ENDPOINT,
        "contract_id": contract_id,
        "manifest_id": manifest_id,
    }
    with open("/app/agent-config.json", "w") as f:
        json.dump(agent_config, f, indent=2)
    print("  Agent config written")

    print("\n" + "=" * 60)
    print("Setup complete. Agent can now process documents.")
    print("=" * 60)


if __name__ == "__main__":
    main()
