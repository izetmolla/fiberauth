package fiberauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/redis/go-redis/v9"
)

func (a *Authorization) GetSession(sessionID string) (*SessionData, error) {
	return a.GetSessionFromDB(sessionID)
}

// GetSessionFromRedis retrieves session data from Redis cache.
// Returns the session data if found, or redis.Nil if not found.
//
// Parameters:
//   - sessionID: The unique session identifier
//
// Returns:
//   - *SessionData: Session data if found
//   - error: Error if session not found or Redis error occurs
//
// Example:
//
//	session, err := auth.GetSessionFromRedis("session-123")
//	if err != nil {
//	    // Handle error
//	}
func (a *Authorization) GetSessionFromRedis(sessionID string) (*SessionData, error) {
	if sessionID == "" {
		return nil, fmt.Errorf("session ID cannot be empty")
	}

	redisKey := buildRedisKey(a.redisPrefix, sessionID)
	data, err := a.redisStorage.Get(context.Background(), redisKey).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, redis.Nil
		}
		return nil, err
	}

	return deserializeSessionData([]byte(data))
}

// SetSessionToRedis stores session data in Redis cache.
// Validates session data before storing and uses configured TTL.
//
// Parameters:
//   - session: The session data to store
//
// Returns:
//   - error: Error if storage fails
//
// Example:
//
//	err := auth.SetSessionToRedis(sessionData)
//	if err != nil {
//	    // Handle error
//	}
func (a *Authorization) SetSessionToRedis(session *SessionData) error {
	if err := validateSessionData(session); err != nil {
		return err
	}

	redisKey := buildRedisKey(a.redisPrefix, session.ID)
	data, err := serializeSessionData(session)
	if err != nil {
		return err
	}

	if err := a.redisStorage.Set(context.Background(), redisKey, data, a.redisTTL).Err(); err != nil {
		return err
	}

	return nil
}

// DeleteSessionFromRedis removes session data from Redis cache.
// This function is currently a placeholder and returns nil.
//
// Parameters:
//   - sessionID: The unique session identifier
//
// Returns:
//   - error: Error if deletion fails
//
// Example:
//
//	err := auth.DeleteSessionFromRedis("session-123")
//	if err != nil {
//	    // Handle error
//	}
func (a *Authorization) DeleteSessionFromRedis(sessionID string) error {
	if sessionID == "" {
		return fmt.Errorf("session ID cannot be empty")
	}

	redisKey := buildRedisKey(a.redisPrefix, sessionID)
	return a.redisStorage.Del(context.Background(), redisKey).Err()
}

// ClearAllSessionsFromRedis removes all session data from Redis cache.
// This function is currently a placeholder and returns nil.
//
// Returns:
//   - error: Error if clearing fails
//
// Example:
//
//	err := auth.ClearAllSessionsFromRedis()
//	if err != nil {
//	    // Handle error
//	}
func (a *Authorization) ClearAllSessionsFromRedis() error {
	pattern := buildRedisKey(a.redisPrefix, "*")
	keys, err := a.redisStorage.Keys(context.Background(), pattern).Result()
	if err != nil {
		return err
	}

	if len(keys) > 0 {
		return a.redisStorage.Del(context.Background(), keys...).Err()
	}
	return nil
}

// GetSessionFromDB retrieves a session from the database with Redis caching.
// Implements a cache-first strategy: checks Redis first, then falls back to database.
// If the session is found in the database, it's cached in Redis for future requests.
//
// Parameters:
//   - sessionID: The unique session identifier
//
// Returns:
//   - *SessionData: Session data if found
//   - error: Error if session not found or database error occurs
//
// Example:
//
//	session, err := auth.GetSessionFromDB("session-123")
//	if err != nil {
//	    // Handle error
//	}
func (a *Authorization) GetSessionFromDB(sessionID string) (*SessionData, error) {
	if sessionID == "" {
		return nil, fmt.Errorf("session ID cannot be empty")
	}
	if a.redisStorage == nil {
		return a.getSessionFromDatabase(sessionID)
	}

	// First try to get from Redis cache for better performance
	session, err := a.GetSessionFromRedis(sessionID)
	if err != nil {
		if errors.Is(err, redis.Nil) {
			// Cache miss - query database and cache the result
			return a.getSessionFromDatabase(sessionID)
		}
		return nil, err
	}
	return session, nil
}

// validateSessionData validates session data for required fields.
// This helper function ensures data integrity before caching or returning session data.
//
// Parameters:
//   - session: The session data to validate
//
// Returns:
//   - error: Error if validation fails
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
// This helper function ensures consistent key generation across the application.
//
// Parameters:
//   - prefix: The key prefix from configuration
//   - sessionID: The session identifier
//
// Returns:
//   - string: The formatted Redis key
func buildRedisKey(prefix, sessionID string) string {
	return fmt.Sprintf("%s:%s", prefix, sessionID)
}

// serializeSessionData serializes session data to JSON for Redis storage.
// This helper function handles JSON marshaling with proper error handling.
//
// Parameters:
//   - session: The session data to serialize
//
// Returns:
//   - []byte: The serialized JSON data
//   - error: Error if serialization fails
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
// This helper function handles JSON unmarshaling with proper error handling.
//
// Parameters:
//   - data: The JSON data to deserialize
//
// Returns:
//   - *SessionData: The deserialized session data
//   - error: Error if deserialization fails
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

// getSessionFromDatabase queries the database for session data and caches the result.
// This is a fallback method when Redis cache misses occur.
// The method uses raw SQL for better performance and control over the query.
//
// Parameters:
//   - sessionID: The unique session identifier
//
// Returns:
//   - *SessionData: Session data if found
//   - error: Error if session not found or database error occurs
func (a *Authorization) getSessionFromDatabase(sessionID string) (*SessionData, error) {
	var sessionData *SessionData
	// Execute raw SQL query to get session and user data
	if err := a.sqlStorage.Raw("SELECT s.id, s.user_id, u.roles, u.metadata FROM sessions s LEFT JOIN users u ON s.user_id = u.id WHERE s.id = ? AND s.expires_at > NOW() AND s.deleted_at IS NULL", sessionID).Scan(&sessionData).Error; err != nil {
		return nil, err
	}

	// Check if session exists in the database
	if sessionData == nil {
		return nil, ErrUnauthorized
	}

	a.setRedisSession(sessionData)
	return sessionData, nil
}
