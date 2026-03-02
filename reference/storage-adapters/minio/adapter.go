// Package minio implements a DSP storage adapter backed by MinIO S3-compatible storage.
//
// It maps DSP storage binding operations (ListDocuments, GrantAccess, ReadDocument,
// VerifyIntegrity) onto the MinIO Go SDK, translating between DSP document semantics
// and S3 object semantics.
package minio

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"strings"
	"time"

	miniogo "github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

// ---------------------------------------------------------------------------
// Domain types
// ---------------------------------------------------------------------------

// Config holds MinIO connection configuration.
type Config struct {
	Endpoint       string
	AccessKeyID    string
	SecretAccessKey string
	Bucket         string
	Prefix         string
	UseSSL         bool
	Region         string
}

// HashDigest represents a content hash in DSP format.
type HashDigest struct {
	Algorithm string `json:"algorithm"`
	Value     string `json:"value"`
}

// DocumentEntry represents metadata about a document stored in MinIO.
type DocumentEntry struct {
	DocumentID     string            `json:"document_id"`
	Classification string            `json:"classification"`
	Sensitivity    string            `json:"sensitivity"`
	Format         string            `json:"format"`
	PageCount      int               `json:"page_count,omitempty"`
	Language       string            `json:"language,omitempty"`
	Hash           HashDigest        `json:"hash"`
	SizeBytes      int64             `json:"size_bytes"`
	CreatedAt      string            `json:"created_at"`
	Tags           map[string]string `json:"tags,omitempty"`
}

// ScopedToken represents a time-limited access token granting access to a set
// of documents for a set of operations.
type ScopedToken struct {
	Token       string   `json:"token"`
	DocumentIDs []string `json:"document_ids"`
	Operations  []string `json:"operations"`
	ExpiresAt   string   `json:"expires_at"`
}

// IntegrityResult represents the result of an integrity check.
type IntegrityResult struct {
	Matches    bool       `json:"matches"`
	ActualHash HashDigest `json:"actual_hash"`
}

// DocumentFilter controls which documents are returned by ListDocuments.
type DocumentFilter struct {
	Classification string
	Sensitivity    string
	Format         string
	Tags           map[string]string
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

// tokenPayload is the JSON structure embedded inside a ScopedToken.Token.
// In a production system this would be a signed JWT or STS credential; for the
// reference implementation we use a simple JSON blob encoded as hex.
type tokenPayload struct {
	PresignedURLs map[string]string `json:"presigned_urls"` // documentID -> presigned URL
	DocumentIDs   []string          `json:"document_ids"`
	Operations    []string          `json:"operations"`
	ExpiresAt     string            `json:"expires_at"`
}

// ---------------------------------------------------------------------------
// Adapter
// ---------------------------------------------------------------------------

// Adapter implements DSP storage operations using MinIO.
type Adapter struct {
	client *miniogo.Client
	config Config
}

// New creates a new MinIO storage adapter.
func New(cfg Config) (*Adapter, error) {
	client, err := miniogo.New(cfg.Endpoint, &miniogo.Options{
		Creds:  credentials.NewStaticV4(cfg.AccessKeyID, cfg.SecretAccessKey, ""),
		Secure: cfg.UseSSL,
		Region: cfg.Region,
	})
	if err != nil {
		return nil, fmt.Errorf("minio adapter: failed to create client: %w", err)
	}

	return &Adapter{
		client: client,
		config: cfg,
	}, nil
}

// NewWithClient creates an Adapter using a pre-configured *miniogo.Client.
// This is primarily useful for testing.
func NewWithClient(client *miniogo.Client, cfg Config) *Adapter {
	return &Adapter{
		client: client,
		config: cfg,
	}
}

// ---------------------------------------------------------------------------
// documentID helpers
// ---------------------------------------------------------------------------

// documentIDFromKey produces a deterministic, opaque document ID from a
// bucket name and object key.  The caller never sees the raw S3 path.
func documentIDFromKey(bucket, key string) string {
	h := sha256.Sum256([]byte(bucket + "/" + key))
	return hex.EncodeToString(h[:])
}

// objectKeyFromPrefix returns the full object key given the adapter prefix
// and a relative key.
func (a *Adapter) objectKeyFromPrefix(relative string) string {
	if a.config.Prefix == "" {
		return relative
	}
	return strings.TrimRight(a.config.Prefix, "/") + "/" + relative
}

// ---------------------------------------------------------------------------
// 1. ListDocuments
// ---------------------------------------------------------------------------

// ListDocuments enumerates objects under the configured bucket/prefix and maps
// each one to a DSP DocumentEntry.  An optional filter narrows results.
func (a *Adapter) ListDocuments(ctx context.Context, scope string, filter *DocumentFilter) ([]DocumentEntry, error) {
	prefix := a.config.Prefix
	if scope != "" {
		if prefix != "" {
			prefix = strings.TrimRight(prefix, "/") + "/" + scope
		} else {
			prefix = scope
		}
	}

	opts := miniogo.ListObjectsOptions{
		Prefix:    prefix,
		Recursive: true,
	}

	var entries []DocumentEntry

	for obj := range a.client.ListObjects(ctx, a.config.Bucket, opts) {
		if obj.Err != nil {
			return nil, fmt.Errorf("minio adapter: list error: %w", obj.Err)
		}

		// Skip "directory" markers.
		if strings.HasSuffix(obj.Key, "/") {
			continue
		}

		// Fetch full object metadata.
		info, err := a.client.StatObject(ctx, a.config.Bucket, obj.Key, miniogo.StatObjectOptions{})
		if err != nil {
			return nil, fmt.Errorf("minio adapter: stat %q: %w", obj.Key, err)
		}

		entry := a.objectInfoToEntry(info)

		// Apply filter.
		if filter != nil && !matchesFilter(entry, filter) {
			continue
		}

		entries = append(entries, entry)
	}

	return entries, nil
}

// objectInfoToEntry converts a MinIO ObjectInfo into a DSP DocumentEntry.
func (a *Adapter) objectInfoToEntry(info miniogo.ObjectInfo) DocumentEntry {
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

	language := meta["Dsp-Language"]

	// Use a stored SHA-256 if available; fall back to ETag.
	hash := HashDigest{Algorithm: "sha256"}
	if stored := meta["Dsp-Sha256"]; stored != "" {
		hash.Value = stored
	} else {
		// ETag is typically the MD5 of a single-part upload.
		hash.Algorithm = "etag"
		hash.Value = strings.Trim(info.ETag, "\"")
	}

	tags := make(map[string]string)
	for k, v := range meta {
		if strings.HasPrefix(k, "Dsp-Tag-") {
			tags[strings.TrimPrefix(k, "Dsp-Tag-")] = v
		}
	}

	return DocumentEntry{
		DocumentID:     documentIDFromKey(a.config.Bucket, info.Key),
		Classification: classification,
		Sensitivity:    sensitivity,
		Format:         format,
		Language:       language,
		Hash:           hash,
		SizeBytes:      info.Size,
		CreatedAt:      info.LastModified.UTC().Format(time.RFC3339),
		Tags:           tags,
	}
}

// matchesFilter returns true when the entry satisfies all non-empty filter
// fields.
func matchesFilter(e DocumentEntry, f *DocumentFilter) bool {
	if f.Classification != "" && e.Classification != f.Classification {
		return false
	}
	if f.Sensitivity != "" && e.Sensitivity != f.Sensitivity {
		return false
	}
	if f.Format != "" && e.Format != f.Format {
		return false
	}
	for k, v := range f.Tags {
		if e.Tags[k] != v {
			return false
		}
	}
	return true
}

// ---------------------------------------------------------------------------
// 2. GrantAccess
// ---------------------------------------------------------------------------

// GrantAccess creates a ScopedToken that grants the specified operations on the
// given documents for the requested duration.
//
// In a production deployment this should use MinIO STS AssumeRoleWithWebIdentity
// to produce short-lived S3 credentials scoped to the requested keys.  The
// reference implementation generates presigned URLs and bundles them into a
// hex-encoded JSON token.
func (a *Adapter) GrantAccess(
	ctx context.Context,
	documentIDs []string,
	agentID string,
	operations []string,
	ttlSeconds int,
	attestation string,
) (*ScopedToken, error) {
	if len(documentIDs) == 0 {
		return nil, fmt.Errorf("minio adapter: at least one document ID is required")
	}
	if ttlSeconds <= 0 {
		return nil, fmt.Errorf("minio adapter: ttlSeconds must be positive")
	}

	expiry := time.Duration(ttlSeconds) * time.Second
	expiresAt := time.Now().UTC().Add(expiry)

	// Build a reverse mapping from documentID -> object key so that we can
	// generate presigned URLs.  We need to walk the bucket to find the keys
	// that match the requested document IDs.
	keyMap, err := a.resolveDocumentIDs(ctx, documentIDs)
	if err != nil {
		return nil, err
	}

	presigned := make(map[string]string, len(documentIDs))
	for _, docID := range documentIDs {
		key, ok := keyMap[docID]
		if !ok {
			return nil, fmt.Errorf("minio adapter: document %q not found", docID)
		}

		reqParams := make(url.Values)
		reqParams.Set("X-Dsp-Agent", agentID)

		u, err := a.client.PresignedGetObject(ctx, a.config.Bucket, key, expiry, reqParams)
		if err != nil {
			return nil, fmt.Errorf("minio adapter: presign %q: %w", docID, err)
		}
		presigned[docID] = u.String()
	}

	payload := tokenPayload{
		PresignedURLs: presigned,
		DocumentIDs:   documentIDs,
		Operations:    operations,
		ExpiresAt:     expiresAt.Format(time.RFC3339),
	}

	raw, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("minio adapter: marshal token: %w", err)
	}

	return &ScopedToken{
		Token:       hex.EncodeToString(raw),
		DocumentIDs: documentIDs,
		Operations:  operations,
		ExpiresAt:   expiresAt.Format(time.RFC3339),
	}, nil
}

// resolveDocumentIDs walks the bucket/prefix and returns a map from
// documentID -> object key for the requested IDs.
func (a *Adapter) resolveDocumentIDs(ctx context.Context, documentIDs []string) (map[string]string, error) {
	wanted := make(map[string]struct{}, len(documentIDs))
	for _, id := range documentIDs {
		wanted[id] = struct{}{}
	}

	result := make(map[string]string, len(documentIDs))

	opts := miniogo.ListObjectsOptions{
		Prefix:    a.config.Prefix,
		Recursive: true,
	}

	for obj := range a.client.ListObjects(ctx, a.config.Bucket, opts) {
		if obj.Err != nil {
			return nil, fmt.Errorf("minio adapter: list error: %w", obj.Err)
		}
		if strings.HasSuffix(obj.Key, "/") {
			continue
		}

		id := documentIDFromKey(a.config.Bucket, obj.Key)
		if _, ok := wanted[id]; ok {
			result[id] = obj.Key
		}

		// Short-circuit when we have found all requested IDs.
		if len(result) == len(documentIDs) {
			break
		}
	}

	return result, nil
}

// ---------------------------------------------------------------------------
// 3. ReadDocument
// ---------------------------------------------------------------------------

// ReadDocument validates the supplied access token and returns an io.ReadCloser
// streaming the requested document content.
//
// The accessToken is the hex-encoded JSON token produced by GrantAccess.
// documentID selects which document to read from the token's scope.
func (a *Adapter) ReadDocument(ctx context.Context, accessToken string, documentID string) (io.ReadCloser, error) {
	payload, err := decodeToken(accessToken)
	if err != nil {
		return nil, fmt.Errorf("minio adapter: invalid token: %w", err)
	}

	// Check expiry.
	expiresAt, err := time.Parse(time.RFC3339, payload.ExpiresAt)
	if err != nil {
		return nil, fmt.Errorf("minio adapter: bad expiry in token: %w", err)
	}
	if time.Now().UTC().After(expiresAt) {
		return nil, fmt.Errorf("minio adapter: token expired at %s", payload.ExpiresAt)
	}

	// Check that the requested document is in scope.
	if !contains(payload.DocumentIDs, documentID) {
		return nil, fmt.Errorf("minio adapter: document %q not in token scope", documentID)
	}

	// Check that "read" is an allowed operation.
	if !contains(payload.Operations, "read") {
		return nil, fmt.Errorf("minio adapter: operation \"read\" not granted by token")
	}

	// Resolve the document ID to an object key. We already stored the
	// presigned URL in the token, but for the direct SDK path we resolve
	// the key again to avoid depending on the presigned URL format.
	keyMap, err := a.resolveDocumentIDs(ctx, []string{documentID})
	if err != nil {
		return nil, err
	}
	key, ok := keyMap[documentID]
	if !ok {
		return nil, fmt.Errorf("minio adapter: document %q not found", documentID)
	}

	obj, err := a.client.GetObject(ctx, a.config.Bucket, key, miniogo.GetObjectOptions{})
	if err != nil {
		return nil, fmt.Errorf("minio adapter: get object %q: %w", key, err)
	}

	return obj, nil
}

// decodeToken reverses the hex-encoded JSON token produced by GrantAccess.
func decodeToken(token string) (*tokenPayload, error) {
	raw, err := hex.DecodeString(token)
	if err != nil {
		return nil, fmt.Errorf("hex decode: %w", err)
	}

	var p tokenPayload
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, fmt.Errorf("json unmarshal: %w", err)
	}
	return &p, nil
}

// contains returns true if slice s contains value v.
func contains(s []string, v string) bool {
	for _, item := range s {
		if item == v {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// 4. VerifyIntegrity
// ---------------------------------------------------------------------------

// VerifyIntegrity checks whether the stored hash for the given document
// matches the expected hash.
func (a *Adapter) VerifyIntegrity(ctx context.Context, documentID string, expectedHash HashDigest) (*IntegrityResult, error) {
	keyMap, err := a.resolveDocumentIDs(ctx, []string{documentID})
	if err != nil {
		return nil, err
	}
	key, ok := keyMap[documentID]
	if !ok {
		return nil, fmt.Errorf("minio adapter: document %q not found", documentID)
	}

	info, err := a.client.StatObject(ctx, a.config.Bucket, key, miniogo.StatObjectOptions{})
	if err != nil {
		return nil, fmt.Errorf("minio adapter: stat %q: %w", key, err)
	}

	actual := a.actualHash(info)

	matches := actual.Algorithm == expectedHash.Algorithm &&
		strings.EqualFold(actual.Value, expectedHash.Value)

	return &IntegrityResult{
		Matches:    matches,
		ActualHash: actual,
	}, nil
}

// actualHash extracts the best available hash from an ObjectInfo.
func (a *Adapter) actualHash(info miniogo.ObjectInfo) HashDigest {
	if stored := info.UserMetadata["Dsp-Sha256"]; stored != "" {
		return HashDigest{Algorithm: "sha256", Value: stored}
	}
	return HashDigest{
		Algorithm: "etag",
		Value:     strings.Trim(info.ETag, "\""),
	}
}
