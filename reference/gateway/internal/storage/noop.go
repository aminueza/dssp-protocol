package storage

import (
	"context"
)

// NoopAdapter is a pass-through adapter used when no storage backend is configured.
// It allows the gateway to function for protocol testing without actual document storage.
// All verification calls succeed and all listing calls return empty results.
type NoopAdapter struct{}

// NewNoopAdapter creates a new NoopAdapter.
func NewNoopAdapter() *NoopAdapter {
	return &NoopAdapter{}
}

func (n *NoopAdapter) ListDocuments(ctx context.Context) ([]DocumentInfo, error) {
	return nil, nil
}

func (n *NoopAdapter) VerifyDocument(ctx context.Context, documentID string) (*DocumentInfo, error) {
	return &DocumentInfo{DocumentID: documentID}, nil
}

func (n *NoopAdapter) GeneratePresignedURL(ctx context.Context, documentID string, ttlSeconds int) (string, error) {
	return "", nil // No actual URL in noop mode
}

func (n *NoopAdapter) VerifyIntegrity(ctx context.Context, documentID string, expectedHash string) (bool, error) {
	return true, nil // Always passes in noop mode
}
