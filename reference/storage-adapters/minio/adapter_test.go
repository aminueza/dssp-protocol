package minio

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// buildTestToken creates a hex-encoded token payload for testing ReadDocument
// without calling GrantAccess (which requires a live MinIO connection).
func buildTestToken(docIDs []string, ops []string, expiresAt time.Time, urls map[string]string) string {
	p := tokenPayload{
		PresignedURLs: urls,
		DocumentIDs:   docIDs,
		Operations:    ops,
		ExpiresAt:     expiresAt.Format(time.RFC3339),
	}
	raw, _ := json.Marshal(p)
	return hex.EncodeToString(raw)
}

// ---------------------------------------------------------------------------
// Unit tests for pure functions (no MinIO server required)
// ---------------------------------------------------------------------------

func TestDocumentIDFromKey_Deterministic(t *testing.T) {
	id1 := documentIDFromKey("bucket", "path/to/file.pdf")
	id2 := documentIDFromKey("bucket", "path/to/file.pdf")
	if id1 != id2 {
		t.Fatalf("expected deterministic IDs, got %q and %q", id1, id2)
	}
}

func TestDocumentIDFromKey_DifferentInputs(t *testing.T) {
	id1 := documentIDFromKey("bucket-a", "doc.pdf")
	id2 := documentIDFromKey("bucket-b", "doc.pdf")
	if id1 == id2 {
		t.Fatal("different buckets should produce different IDs")
	}

	id3 := documentIDFromKey("bucket-a", "doc1.pdf")
	id4 := documentIDFromKey("bucket-a", "doc2.pdf")
	if id3 == id4 {
		t.Fatal("different keys should produce different IDs")
	}
}

func TestDocumentIDFromKey_IsHex(t *testing.T) {
	id := documentIDFromKey("b", "k")
	if _, err := hex.DecodeString(id); err != nil {
		t.Fatalf("expected hex string, got %q: %v", id, err)
	}
	// SHA-256 produces 64 hex characters.
	if len(id) != 64 {
		t.Fatalf("expected 64 hex chars, got %d", len(id))
	}
}

func TestContains(t *testing.T) {
	cases := []struct {
		slice    []string
		value    string
		expected bool
	}{
		{[]string{"a", "b", "c"}, "b", true},
		{[]string{"a", "b", "c"}, "d", false},
		{[]string{}, "a", false},
		{nil, "a", false},
	}
	for _, tc := range cases {
		got := contains(tc.slice, tc.value)
		if got != tc.expected {
			t.Errorf("contains(%v, %q) = %v, want %v", tc.slice, tc.value, got, tc.expected)
		}
	}
}

func TestMatchesFilter_Empty(t *testing.T) {
	entry := DocumentEntry{Classification: "public", Sensitivity: "low", Format: "application/pdf"}
	if !matchesFilter(entry, &DocumentFilter{}) {
		t.Fatal("empty filter should match everything")
	}
}

func TestMatchesFilter_Classification(t *testing.T) {
	entry := DocumentEntry{Classification: "public", Sensitivity: "low", Format: "application/pdf"}

	if !matchesFilter(entry, &DocumentFilter{Classification: "public"}) {
		t.Fatal("should match classification=public")
	}
	if matchesFilter(entry, &DocumentFilter{Classification: "confidential"}) {
		t.Fatal("should not match classification=confidential")
	}
}

func TestMatchesFilter_Sensitivity(t *testing.T) {
	entry := DocumentEntry{Classification: "public", Sensitivity: "low", Format: "application/pdf"}

	if !matchesFilter(entry, &DocumentFilter{Sensitivity: "low"}) {
		t.Fatal("should match sensitivity=low")
	}
	if matchesFilter(entry, &DocumentFilter{Sensitivity: "high"}) {
		t.Fatal("should not match sensitivity=high")
	}
}

func TestMatchesFilter_Format(t *testing.T) {
	entry := DocumentEntry{Classification: "public", Sensitivity: "low", Format: "application/pdf"}

	if !matchesFilter(entry, &DocumentFilter{Format: "application/pdf"}) {
		t.Fatal("should match format")
	}
	if matchesFilter(entry, &DocumentFilter{Format: "text/plain"}) {
		t.Fatal("should not match wrong format")
	}
}

func TestMatchesFilter_Tags(t *testing.T) {
	entry := DocumentEntry{
		Classification: "public",
		Tags:           map[string]string{"dept": "legal", "year": "2025"},
	}

	if !matchesFilter(entry, &DocumentFilter{Tags: map[string]string{"dept": "legal"}}) {
		t.Fatal("should match tag subset")
	}
	if matchesFilter(entry, &DocumentFilter{Tags: map[string]string{"dept": "hr"}}) {
		t.Fatal("should not match wrong tag value")
	}
	if matchesFilter(entry, &DocumentFilter{Tags: map[string]string{"missing": "x"}}) {
		t.Fatal("should not match missing tag")
	}
}

func TestMatchesFilter_Combined(t *testing.T) {
	entry := DocumentEntry{
		Classification: "internal",
		Sensitivity:    "medium",
		Format:         "application/pdf",
		Tags:           map[string]string{"dept": "eng"},
	}

	f := &DocumentFilter{
		Classification: "internal",
		Sensitivity:    "medium",
		Format:         "application/pdf",
		Tags:           map[string]string{"dept": "eng"},
	}
	if !matchesFilter(entry, f) {
		t.Fatal("should match all fields")
	}

	f2 := &DocumentFilter{
		Classification: "internal",
		Sensitivity:    "high", // mismatch
	}
	if matchesFilter(entry, f2) {
		t.Fatal("should fail on sensitivity mismatch")
	}
}

// ---------------------------------------------------------------------------
// Token encode / decode round-trip
// ---------------------------------------------------------------------------

func TestDecodeToken_RoundTrip(t *testing.T) {
	docIDs := []string{"abc123", "def456"}
	ops := []string{"read", "list"}
	exp := time.Now().UTC().Add(1 * time.Hour)
	urls := map[string]string{
		"abc123": "https://minio.example.com/bucket/obj1?token=xxx",
		"def456": "https://minio.example.com/bucket/obj2?token=yyy",
	}

	token := buildTestToken(docIDs, ops, exp, urls)

	decoded, err := decodeToken(token)
	if err != nil {
		t.Fatalf("decodeToken: %v", err)
	}

	if len(decoded.DocumentIDs) != 2 {
		t.Fatalf("expected 2 document IDs, got %d", len(decoded.DocumentIDs))
	}
	if decoded.DocumentIDs[0] != "abc123" {
		t.Fatalf("expected abc123, got %q", decoded.DocumentIDs[0])
	}
	if len(decoded.Operations) != 2 {
		t.Fatalf("expected 2 operations, got %d", len(decoded.Operations))
	}
	if decoded.PresignedURLs["abc123"] != urls["abc123"] {
		t.Fatalf("presigned URL mismatch")
	}
}

func TestDecodeToken_Invalid(t *testing.T) {
	// Not valid hex.
	if _, err := decodeToken("not-hex!!"); err == nil {
		t.Fatal("expected error for invalid hex")
	}

	// Valid hex but not valid JSON.
	if _, err := decodeToken(hex.EncodeToString([]byte("not json"))); err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

// ---------------------------------------------------------------------------
// Token validation logic (mirrors ReadDocument checks)
// ---------------------------------------------------------------------------

func TestTokenExpiry(t *testing.T) {
	// Expired token.
	expired := time.Now().UTC().Add(-1 * time.Hour)
	token := buildTestToken([]string{"doc1"}, []string{"read"}, expired, nil)

	payload, err := decodeToken(token)
	if err != nil {
		t.Fatalf("decodeToken: %v", err)
	}

	expiresAt, _ := time.Parse(time.RFC3339, payload.ExpiresAt)
	if !time.Now().UTC().After(expiresAt) {
		t.Fatal("expected token to be expired")
	}
}

func TestTokenScopeCheck(t *testing.T) {
	token := buildTestToken([]string{"doc1", "doc2"}, []string{"read"}, time.Now().Add(time.Hour), nil)
	payload, _ := decodeToken(token)

	if !contains(payload.DocumentIDs, "doc1") {
		t.Fatal("doc1 should be in scope")
	}
	if contains(payload.DocumentIDs, "doc3") {
		t.Fatal("doc3 should not be in scope")
	}
}

func TestTokenOperationCheck(t *testing.T) {
	token := buildTestToken([]string{"doc1"}, []string{"read", "list"}, time.Now().Add(time.Hour), nil)
	payload, _ := decodeToken(token)

	if !contains(payload.Operations, "read") {
		t.Fatal("read should be allowed")
	}
	if contains(payload.Operations, "write") {
		t.Fatal("write should not be allowed")
	}
}

// ---------------------------------------------------------------------------
// Adapter constructor
// ---------------------------------------------------------------------------

func TestNew_InvalidEndpoint(t *testing.T) {
	// New should succeed even with a bogus endpoint because the MinIO client
	// does not connect eagerly.  We just verify it returns without error.
	adapter, err := New(Config{
		Endpoint:       "localhost:9999",
		AccessKeyID:    "test",
		SecretAccessKey: "test",
		Bucket:         "test",
		UseSSL:         false,
	})
	if err != nil {
		t.Fatalf("New: unexpected error: %v", err)
	}
	if adapter == nil {
		t.Fatal("expected non-nil adapter")
	}
	if adapter.config.Bucket != "test" {
		t.Fatalf("expected bucket=test, got %q", adapter.config.Bucket)
	}
}

// ---------------------------------------------------------------------------
// objectKeyFromPrefix
// ---------------------------------------------------------------------------

func TestObjectKeyFromPrefix_NoPrefix(t *testing.T) {
	a := &Adapter{config: Config{Prefix: ""}}
	got := a.objectKeyFromPrefix("file.pdf")
	if got != "file.pdf" {
		t.Fatalf("expected file.pdf, got %q", got)
	}
}

func TestObjectKeyFromPrefix_WithPrefix(t *testing.T) {
	a := &Adapter{config: Config{Prefix: "documents"}}
	got := a.objectKeyFromPrefix("file.pdf")
	if got != "documents/file.pdf" {
		t.Fatalf("expected documents/file.pdf, got %q", got)
	}
}

func TestObjectKeyFromPrefix_TrailingSlash(t *testing.T) {
	a := &Adapter{config: Config{Prefix: "documents/"}}
	got := a.objectKeyFromPrefix("file.pdf")
	if got != "documents/file.pdf" {
		t.Fatalf("expected documents/file.pdf, got %q", got)
	}
}

// ---------------------------------------------------------------------------
// IntegrityResult construction
// ---------------------------------------------------------------------------

func TestIntegrityResult_Match(t *testing.T) {
	actual := HashDigest{Algorithm: "sha256", Value: "abcdef1234567890"}
	expected := HashDigest{Algorithm: "sha256", Value: "ABCDEF1234567890"}

	matches := actual.Algorithm == expected.Algorithm &&
		strings.EqualFold(actual.Value, expected.Value)
	if !matches {
		t.Fatal("case-insensitive hex comparison should match")
	}
}

func TestIntegrityResult_Mismatch_Algorithm(t *testing.T) {
	actual := HashDigest{Algorithm: "sha256", Value: "abcdef"}
	expected := HashDigest{Algorithm: "etag", Value: "abcdef"}

	matches := actual.Algorithm == expected.Algorithm &&
		strings.EqualFold(actual.Value, expected.Value)
	if matches {
		t.Fatal("different algorithms should not match")
	}
}

func TestIntegrityResult_Mismatch_Value(t *testing.T) {
	actual := HashDigest{Algorithm: "sha256", Value: "aaa"}
	expected := HashDigest{Algorithm: "sha256", Value: "bbb"}

	matches := actual.Algorithm == expected.Algorithm &&
		strings.EqualFold(actual.Value, expected.Value)
	if matches {
		t.Fatal("different values should not match")
	}
}

// ---------------------------------------------------------------------------
// GrantAccess input validation (does not need a live server)
// ---------------------------------------------------------------------------

func TestGrantAccess_NoDocumentIDs(t *testing.T) {
	a := &Adapter{config: Config{Bucket: "test"}}
	_, err := a.GrantAccess(context.Background(), nil, "agent-1", []string{"read"}, 3600, "")
	if err == nil {
		t.Fatal("expected error for empty document IDs")
	}
	if !strings.Contains(err.Error(), "at least one document ID") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestGrantAccess_InvalidTTL(t *testing.T) {
	a := &Adapter{config: Config{Bucket: "test"}}
	_, err := a.GrantAccess(context.Background(), []string{"doc1"}, "agent-1", []string{"read"}, 0, "")
	if err == nil {
		t.Fatal("expected error for zero TTL")
	}
	if !strings.Contains(err.Error(), "ttlSeconds must be positive") {
		t.Fatalf("unexpected error: %v", err)
	}
}
