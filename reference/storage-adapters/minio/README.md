# DSP MinIO Storage Adapter

Maps DSP storage operations to MinIO S3-compatible API.

## Usage

```go
adapter, err := minio.New(minio.Config{
    Endpoint:       "localhost:9000",
    AccessKeyID:    "minioadmin",
    SecretAccessKey: "minioadmin",
    Bucket:         "dsp-documents",
    UseSSL:         false,
})

documents, err := adapter.ListDocuments(ctx, scope, filter)
token, err := adapter.GrantAccess(ctx, docIDs, agentID, ops, 3600, attestation)
```

## Configuration

| Env Var | Description | Default |
|---------|-------------|---------|
| `MINIO_ENDPOINT` | MinIO server endpoint | `localhost:9000` |
| `MINIO_ACCESS_KEY` | Access key | required |
| `MINIO_SECRET_KEY` | Secret key | required |
| `MINIO_BUCKET` | Document bucket | `dsp-documents` |
| `MINIO_PREFIX` | Object key prefix | `` |
| `MINIO_USE_SSL` | Use TLS | `true` |
