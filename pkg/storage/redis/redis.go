// Package redis provides Redis caching operations for authentication.
// This package is isolated to allow users to import authentication without Redis dependencies.
package redis

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// SessionData represents cached session information in Redis.
type SessionData struct {
	ID       string          `json:"id"`
	UserID   string          `json:"user_id"`
	Roles    json.RawMessage `json:"roles"`
	Metadata json.RawMessage `json:"metadata"`
	Options  json.RawMessage `json:"options"`
}

// Manager handles Redis operations for session caching.
type Manager struct {
	client *redis.Client
	prefix string
	ttl    time.Duration
}

// NewManager creates a new Redis manager instance.
//
// Parameters:
//   - client: Redis client instance
//   - prefix: Key prefix for Redis keys (e.g., "AUTHSESSIONS")
//   - ttl: Time-to-live for cached sessions
//
// Returns:
//   - *Manager: Redis manager instance
func NewManager(client *redis.Client, prefix string, ttl time.Duration) *Manager {
	if prefix == "" {
		prefix = "AUTHSESSIONS"
	}
	if ttl == 0 {
		ttl = 30 * time.Minute
	}
	
	return &Manager{
		client: client,
		prefix: prefix,
		ttl:    ttl,
	}
}

// GetSession retrieves session data from Redis cache.
//
// Parameters:
//   - sessionID: The unique session identifier
//
// Returns:
//   - *SessionData: Session data if found
//   - error: Error if session not found or Redis error occurs
func (m *Manager) GetSession(sessionID string) (*SessionData, error) {
	if sessionID == "" {
		return nil, fmt.Errorf("session ID cannot be empty")
	}

	redisKey := buildRedisKey(m.prefix, sessionID)
	data, err := m.client.Get(context.Background(), redisKey).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, redis.Nil
		}
		return nil, err
	}

	return deserializeSessionData([]byte(data))
}

// SetSession stores session data in Redis cache.
//
// Parameters:
//   - session: The session data to store
//
// Returns:
//   - error: Error if storage fails
func (m *Manager) SetSession(session *SessionData) error {
	if err := validateSessionData(session); err != nil {
		return err
	}

	redisKey := buildRedisKey(m.prefix, session.ID)
	data, err := serializeSessionData(session)
	if err != nil {
		return err
	}

	if err := m.client.Set(context.Background(), redisKey, data, m.ttl).Err(); err != nil {
		return err
	}

	return nil
}

// DeleteSession removes session data from Redis cache.
//
// Parameters:
//   - sessionID: The unique session identifier
//
// Returns:
//   - error: Error if deletion fails
func (m *Manager) DeleteSession(sessionID string) error {
	if sessionID == "" {
		return fmt.Errorf("session ID cannot be empty")
	}

	redisKey := buildRedisKey(m.prefix, sessionID)
	return m.client.Del(context.Background(), redisKey).Err()
}

// ClearAllSessions removes all session data from Redis cache.
//
// Returns:
//   - error: Error if clearing fails
func (m *Manager) ClearAllSessions() error {
	pattern := buildRedisKey(m.prefix, "*")
	keys, err := m.client.Keys(context.Background(), pattern).Result()
	if err != nil {
		return err
	}

	if len(keys) > 0 {
		return m.client.Del(context.Background(), keys...).Err()
	}
	return nil
}

// Helper functions

// validateSessionData validates session data for required fields.
func validateSessionData(session *SessionData) error {
	if session == nil {
		return fmt.Errorf("session data cannot be nil")
	}
	if session.ID == "" {
		return fmt.Errorf("session ID cannot be empty")
	}
	if session.UserID == "" {
		return fmt.Errorf("user ID cannot be empty")
	}
	return nil
}

// buildRedisKey creates a Redis key with the configured prefix.
func buildRedisKey(prefix, sessionID string) string {
	return fmt.Sprintf("%s:%s", prefix, sessionID)
}

// serializeSessionData serializes session data to JSON for Redis storage.
func serializeSessionData(session *SessionData) ([]byte, error) {
	if session == nil {
		return nil, fmt.Errorf("session data cannot be nil")
	}

	data, err := json.Marshal(session)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal session data: %w", err)
	}

	return data, nil
}

// deserializeSessionData deserializes JSON data from Redis into session data.
func deserializeSessionData(data []byte) (*SessionData, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("session data is empty")
	}

	var response SessionData
	if err := json.Unmarshal(data, &response); err != nil {
		return nil, fmt.Errorf("failed to unmarshal session data: %w", err)
	}

	return &response, nil
}

