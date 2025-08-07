package fiberauth

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/gofiber/fiber/v3"
)

// =============================================================================
// SESSION MANAGEMENT
// =============================================================================

// SetSessionCookie sets a session cookie in the HTTP response.
// Creates a secure, HTTP-only cookie with the session ID for client-side session management.
//
// Parameters:
//   - c: Fiber context containing the HTTP response
//   - sessionID: The session identifier to store in the cookie
//
// Example:
//
//	auth.SetSessionCookie(c, "session-123")
//	// Sets a secure cookie with the session ID
func (a *Authorization) SetSessionCookie(c fiber.Ctx, sessionID string) {
	cookie := new(fiber.Cookie)
	cookie.Name = a.cookieSessionName
	cookie.Value = sessionID
	// Set Domain to a dot-prefixed base domain to cover all subdomains.
	cookie.Domain = fmt.Sprintf(".%s", a.mainDomainName)
	cookie.Path = "/"
	cookie.Expires = time.Now().Add(365 * 24 * time.Hour)
	cookie.HTTPOnly = true
	cookie.Secure = true
	c.Cookie(cookie)
}

// =============================================================================
// SESSION MANAGER
// =============================================================================

// SessionManager handles common session operations
type SessionManager struct {
	auth *Authorization
}

// NewSessionManager creates a new session manager instance
func NewSessionManager(auth *Authorization) *SessionManager {
	return &SessionManager{auth: auth}
}

// CreateAndStoreSession creates a session and stores it in Redis
func (sm *SessionManager) CreateAndStoreSession(user *User, sessionID string) error {
	sessionData := &SessionData{
		ID:       sessionID,
		UserID:   user.ID,
		Roles:    sm.ensureJSONField(user.Roles, "[]"),
		Metadata: sm.ensureJSONField(user.Metadata, "{}"),
	}

	sm.auth.setRedisSession(sessionData)
	return nil
}

// ensureJSONField ensures a JSON field is not nil
func (sm *SessionManager) ensureJSONField(field json.RawMessage, defaultValue string) json.RawMessage {
	if field == nil {
		return json.RawMessage(defaultValue)
	}
	return field
}

// CreateAuthorizationResponse creates a standardized authorization response
func (sm *SessionManager) CreateAuthorizationResponse(user *User, tokens *Tokens, sessionID string) *AuthorizationResponse {
	return &AuthorizationResponse{
		User:      userResponse(user),
		SessionID: sessionID,
		Tokens:    *tokens,
	}
}
