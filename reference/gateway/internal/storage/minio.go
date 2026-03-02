package storage

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

// MinIOConfig holds MinIO connection configuration.
type MinIOConfig struct {
	Endpoint  string
	AccessKey string
	SecretKey string
	Bucket    string
	Prefix    string
	UseSSL    bool
}

// MinIOAdapter implements the Adapter interface using MinIO S3-compatible storage.
// It wraps the minio-go SDK to provide DSP document storage operations including
// listing, verification, presigned URL generation, and integrity checking.
type MinIOAdapter struct {
	client *minio.Client
	config MinIOConfig
}

// NewMinIOAdapter creates a new MinIOAdapter with the given configuration.
func NewMinIOAdapter(cfg MinIOConfig) (*MinIOAdapter, error) {
	client, err := minio.New(cfg.Endpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(cfg.AccessKey, cfg.SecretKey, ""),
		Secure: cfg.UseSSL,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create MinIO client: %w", err)
	}

	return &MinIOAdapter{
		client: client,
		config: cfg,
	}, nil
}

// documentIDFromKey produces a deterministic, opaque document ID from a
// bucket name and object key. The caller never sees the raw S3 path.
func documentIDFromKey(bucket, key string) string {
	h := sha256.Sum256([]byte(bucket + "/" + key))
	return hex.EncodeToString(h[:])
}

// objectKey returns the full object key given the adapter prefix and a relative key.
func (m *MinIOAdapter) objectKey(relative string) string {
	if m.config.Prefix == "" {
		return relative
	}
	return strings.TrimRight(m.config.Prefix, "/") + "/" + relative
}

// ListDocuments enumerates objects under the configured bucket/prefix and maps
// each one to a DocumentInfo. It calls StatObject for each object to retrieve
// full metadata including user-defined headers.
func (m *MinIOAdapter) ListDocuments(ctx context.Context) ([]DocumentInfo, error) {
	opts := minio.ListObjectsOptions{
		Prefix:    m.config.Prefix,
		Recursive: true,
	}

	var docs []DocumentInfo

	for obj := range m.client.ListObjects(ctx, m.config.Bucket, opts) {
		if obj.Err != nil {
			return nil, fmt.Errorf("minio list error: %w", obj.Err)
		}

		// Skip directory markers.
		if strings.HasSuffix(obj.Key, "/") {
			continue
		}

		info, err := m.client.StatObject(ctx, m.config.Bucket, obj.Key, minio.StatObjectOptions{})
		if err != nil {
			return nil, fmt.Errorf("minio stat %q: %w", obj.Key, err)
		}

		docs = append(docs, m.objectInfoToDocumentInfo(info))
	}

	return docs, nil
}

// VerifyDocument checks if a document exists by resolving its document ID to an
// object key, then calling StatObject. Returns the document metadata if found.
func (m *MinIOAdapter) VerifyDocument(ctx context.Context, documentID string) (*DocumentInfo, error) {
	key, err := m.resolveDocumentID(ctx, documentID)
	if err != nil {
		return nil, err
	}

	info, err := m.client.StatObject(ctx, m.config.Bucket, key, minio.StatObjectOptions{})
	if err != nil {
		return nil, fmt.Errorf("minio stat %q: %w", key, err)
	}

	doc := m.objectInfoToDocumentInfo(info)
	return &doc, nil
}

// GeneratePresignedURL creates a time-limited GET URL for direct document access.
func (m *MinIOAdapter) GeneratePresignedURL(ctx context.Context, documentID string, ttlSeconds int) (string, error) {
	key, err := m.resolveDocumentID(ctx, documentID)
	if err != nil {
		return "", err
	}

	expiry := time.Duration(ttlSeconds) * time.Second
	reqParams := make(url.Values)
	reqParams.Set("X-Dsp-Document-Id", documentID)

	u, err := m.client.PresignedGetObject(ctx, m.config.Bucket, key, expiry, reqParams)
	if err != nil {
		return "", fmt.Errorf("minio presign %q: %w", documentID, err)
	}

	return u.String(), nil
}

// VerifyIntegrity checks whether the stored hash for the given document matches
// the expected SHA-256 hex value. It compares against the Dsp-Sha256 user
// metadata header if available, falling back to the ETag.
func (m *MinIOAdapter) VerifyIntegrity(ctx context.Context, documentID string, expectedHash string) (bool, error) {
	key, err := m.resolveDocumentID(ctx, documentID)
	if err != nil {
		return false, err
	}

	info, err := m.client.StatObject(ctx, m.config.Bucket, key, minio.StatObjectOptions{})
	if err != nil {
		return false, fmt.Errorf("minio stat %q: %w", key, err)
	}

	actualHash := m.extractHash(info)
	return strings.EqualFold(actualHash, expectedHash), nil
}

// resolveDocumentID walks the bucket/prefix to find the object key whose
// deterministic document ID matches the requested ID.
func (m *MinIOAdapter) resolveDocumentID(ctx context.Context, documentID string) (string, error) {
	opts := minio.ListObjectsOptions{
		Prefix:    m.config.Prefix,
		Recursive: true,
	}

	for obj := range m.client.ListObjects(ctx, m.config.Bucket, opts) {
		if obj.Err != nil {
			return "", fmt.Errorf("minio list error: %w", obj.Err)
		}
		if strings.HasSuffix(obj.Key, "/") {
			continue
		}

		id := documentIDFromKey(m.config.Bucket, obj.Key)
		if id == documentID {
			return obj.Key, nil
		}
	}

	return "", fmt.Errorf("document %q not found in bucket %q", documentID, m.config.Bucket)
}

// objectInfoToDocumentInfo converts a MinIO ObjectInfo into a DocumentInfo.
func (m *MinIOAdapter) objectInfoToDocumentInfo(info minio.ObjectInfo) DocumentInfo {
	meta := info.UserMetadata

	classification := meta["Dsp-Classification"]
	if classification == "" {
		classification = "unclassified"
	}

	sensitivity := meta["Dsp-Sensitivity"]
	if sensitivity == "" {
		sensitivity = "none"
	}

	format := meta["Content-Type"]
	if format == "" {
		format = info.ContentType
	}

	hash := m.extractHash(info)

	return DocumentInfo{
		DocumentID:     documentIDFromKey(m.config.Bucket, info.Key),
		Classification: classification,
		Sensitivity:    sensitivity,
		Format:         format,
		SizeBytes:      info.Size,
		Hash:           hash,
	}
}

// extractHash returns the best available hash string from an ObjectInfo.
// Prefers the Dsp-Sha256 user metadata, falling back to ETag.
func (m *MinIOAdapter) extractHash(info minio.ObjectInfo) string {
	if stored := info.UserMetadata["Dsp-Sha256"]; stored != "" {
		return stored
	}
	return strings.Trim(info.ETag, "\"")
}
