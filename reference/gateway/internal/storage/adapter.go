// Package storage defines the document storage adapter interface for the DSSP gateway.
// It maps to the DSSP Storage Binding (Layer 0) operations, abstracting over
// concrete storage backends such as MinIO, S3, Azure Blob, or local filesystem.
package storage

import (
	"context"
)

type DocumentInfo struct {
	DocumentID     string `json:"document_id"`
	Classification string `json:"classification"`
	Sensitivity    string `json:"sensitivity"`
	Format         string `json:"format"`
	SizeBytes      int64  `json:"size_bytes"`
	Hash           string `json:"hash"` // SHA-256 hex
}

// Adapter defines the document storage interface for the DSSP gateway,
// mapping to the DSSP Storage Binding (Layer 0) operations.
type Adapter interface {
	ListDocuments(ctx context.Context) ([]DocumentInfo, error)
	VerifyDocument(ctx context.Context, documentID string) (*DocumentInfo, error)
	GeneratePresignedURL(ctx context.Context, documentID string, ttlSeconds int) (string, error)
	VerifyIntegrity(ctx context.Context, documentID string, expectedHash string) (bool, error)
}
