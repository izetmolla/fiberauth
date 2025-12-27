package fiberauth

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/izetmolla/fiberauth/pkg/storage/redis"
	"github.com/izetmolla/fiberauth/pkg/utils"
	redisclient "github.com/redis/go-redis/v9"
)

// GetSession retrieves session data from cache or database.
//
// Parameters:
//   - sessionID: The unique session identifier
//
// Returns:
//   - *SessionData: Session data if found
//   - error: Error if session not found
func (a *Authorization) GetSession(sessionID string) (*SessionData, error) {
	return a.GetSessionFromDB(sessionID)
}

// GetSessionFromRedis retrieves session data from Redis cache.
//
// Parameters:
//   - sessionID: The unique session identifier
//
// Returns:
//   - *SessionData: Session data if found
//   - error: Error if session not found or Redis error occurs
func (a *Authorization) GetSessionFromRedis(sessionID string) (*SessionData, error) {
	if a.redisManager == nil {
		return nil, fmt.Errorf("Redis is not configured")
	}

	redisSession, err := a.redisManager.GetSession(sessionID)
	if err != nil {
		return nil, err
	}

	return utils.Convert[redis.SessionData, SessionData](redisSession)
}

// SetSessionToRedis stores session data in Redis cache.
//
// Parameters:
//   - session: The session data to store
//
// Returns:
//   - error: Error if storage fails
func (a *Authorization) SetSessionToRedis(session *SessionData) error {
	if a.redisManager == nil {
		return fmt.Errorf("Redis is not configured")
	}

	redisSession, err := utils.Convert[SessionData, redis.SessionData](session)
	if err != nil {
		return err
	}

	return a.redisManager.SetSession(redisSession)
}

// DeleteSessionFromRedis removes session data from Redis cache.
//
// Parameters:
//   - sessionID: The unique session identifier
//
// Returns:
//   - error: Error if deletion fails
func (a *Authorization) DeleteSessionFromRedis(sessionID string) error {
	if a.redisManager == nil {
		return fmt.Errorf("Redis is not configured")
	}

	return a.redisManager.DeleteSession(sessionID)
}

// ClearAllSessionsFromRedis removes all session data from Redis cache.
//
// Returns:
//   - error: Error if clearing fails
func (a *Authorization) ClearAllSessionsFromRedis() error {
	if a.redisManager == nil {
		return fmt.Errorf("Redis is not configured")
	}

	return a.redisManager.ClearAllSessions()
}

// GetSessionFromDB retrieves a session from the database with Redis caching.
// Implements a cache-first strategy: checks Redis first, then falls back to database.
//
// Parameters:
//   - sessionID: The unique session identifier
//
// Returns:
//   - *SessionData: Session data if found
//   - error: Error if session not found or database error occurs
func (a *Authorization) GetSessionFromDB(sessionID string) (*SessionData, error) {
	if sessionID == "" {
		return nil, fmt.Errorf("session ID cannot be empty")
	}

	// Try Redis cache first if available
	if a.redisManager != nil {
		session, err := a.GetSessionFromRedis(sessionID)
		if err == nil {
			return session, nil
		}
		// Continue to database if Redis error (cache miss)
		if err != redisclient.Nil {
			if a.Debug {
				fmt.Printf("Redis error: %v, falling back to database\n", err)
			}
		}
	}

	// Fallback to database
	return a.getSessionFromDatabase(sessionID)
}

// getSessionFromDatabase queries the database for session data and caches the result.
func (a *Authorization) getSessionFromDatabase(sessionID string) (*SessionData, error) {
	// Query Session model
	sess, err := a.dbManager.GetSessionByID(sessionID, time.Now())
	if err != nil {
		return nil, ErrUnauthorized
	}

	// Query User model for roles, metadata, options
	roles, metadata, options, err := a.dbManager.GetUserByID(sess.UserID)
	if err != nil {
		return nil, err
	}

	// Build SessionData
	sessionData := &SessionData{
		ID:       sess.ID,
		UserID:   sess.UserID,
		Roles:    roles,
		Metadata: metadata,
		Options:  options,
	}

	// Cache in Redis if available
	a.setRedisSession(sessionData)

	return sessionData, nil
}

// HandleRefreshToken processes a refresh token from the request context.
//
// Parameters:
//   - c: Fiber context containing the request
//
// Returns:
//   - string: New access token
//   - error: Error if refresh fails
func (a *Authorization) HandleRefreshToken(c fiber.Ctx) (string, error) {
	// Try to get token from header first
	token, err := a.GetTokenFromHeader(c)
	if err != nil {
		// Try to get from request body
		type RefreshRequest struct {
			RefreshToken string `json:"refresh_token"`
		}
		var req RefreshRequest
		if err := c.Bind().Body(&req); err != nil {
			return "", fmt.Errorf("refresh token is required")
		}
		token = req.RefreshToken
	}

	if token == "" {
		return "", fmt.Errorf("refresh token is required")
	}

	return a.RefreshToken(token)
}

// GetTokenFromHeader extracts the JWT token from the Authorization header.
//
// Parameters:
//   - c: Fiber context containing the request headers
//
// Returns:
//   - string: The extracted token
//   - error: Error if token extraction fails
func (a *Authorization) GetTokenFromHeader(c fiber.Ctx) (string, error) {
	authHeader := c.Get("Authorization")
	if authHeader == "" {
		return "", fmt.Errorf("authorization header is required")
	}

	// Check for Bearer token
	if len(authHeader) > 7 && authHeader[:7] == "Bearer " {
		return authHeader[7:], nil
	}

	// Check for Token scheme
	if len(authHeader) > 6 && authHeader[:6] == "Token " {
		return authHeader[6:], nil
	}

	// Return as-is if no scheme is specified
	return authHeader, nil
}

// FormatRoles converts JSON raw message roles to a string slice.
func (a *Authorization) FormatRoles(dbRoles json.RawMessage) []string {
	var roles []string
	if err := json.Unmarshal(dbRoles, &roles); err != nil {
		return []string{}
	}
	return roles
}
