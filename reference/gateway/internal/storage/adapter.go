// Package storage defines the document storage adapter interface for the DSP gateway.
// It maps to the DSP Storage Binding (Layer 0) operations, abstracting over
// concrete storage backends such as MinIO, S3, Azure Blob, or local filesystem.
package storage

import (
	"context"
)

// DocumentInfo holds metadata about a stored document.
type DocumentInfo struct {
	DocumentID     string `json:"document_id"`
	Classification string `json:"classification"`
	Sensitivity    string `json:"sensitivity"`
	Format         string `json:"format"`
	SizeBytes      int64  `json:"size_bytes"`
	Hash           string `json:"hash"` // SHA-256 hex
}

// Adapter defines the document storage interface for the DSP gateway.
// This maps to the DSP Storage Binding (Layer 0) operations.
type Adapter interface {
	// ListDocuments enumerates documents available for processing.
	ListDocuments(ctx context.Context) ([]DocumentInfo, error)

	// VerifyDocument checks if a document exists and returns its metadata.
	VerifyDocument(ctx context.Context, documentID string) (*DocumentInfo, error)

	// GeneratePresignedURL creates a time-limited URL for direct document access.
	GeneratePresignedURL(ctx context.Context, documentID string, ttlSeconds int) (string, error)

	// VerifyIntegrity checks if a document's hash matches the expected value.
	VerifyIntegrity(ctx context.Context, documentID string, expectedHash string) (bool, error)
}
