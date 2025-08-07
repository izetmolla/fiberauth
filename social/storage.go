package social

import (
	"context"
	"time"
)

// StorageInterface defines the interface for storage providers.
// It provides a unified interface for both Redis and GORM storage implementations.
type StorageInterface interface {
	// Get retrieves a value by key using the default context.
	Get(key string) ([]byte, error)

	// GetWithContext retrieves a value by key using the provided context.
	GetWithContext(ctx context.Context, key string) ([]byte, error)

	// Set stores a value with the given key and expiration duration using the default context.
	Set(key string, val []byte, exp time.Duration) error

	// SetWithContext stores a value with the given key and expiration duration using the provided context.
	SetWithContext(ctx context.Context, key string, val []byte, exp time.Duration) error

	// Delete removes a value by key using the default context.
	Delete(key string) error

	// DeleteWithContext removes a value by key using the provided context.
	DeleteWithContext(ctx context.Context, key string) error

	// Reset removes all stored values using the default context.
	Reset() error

	// ResetWithContext removes all stored values using the provided context.
	ResetWithContext(ctx context.Context) error

	// Keys returns all stored keys using the default context.
	Keys() ([][]byte, error)

	// Close closes the storage connection.
	Close() error
}
