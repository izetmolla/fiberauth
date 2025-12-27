// Package session provides session management functionality.
// This package handles session creation, storage, and cookie management.
package session

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/gofiber/fiber/v3"
)

// Data represents session information.
type Data struct {
	ID       string          `json:"id"`
	UserID   string          `json:"user_id"`
	Roles    json.RawMessage `json:"roles"`
	Metadata json.RawMessage `json:"metadata"`
	Options  json.RawMessage `json:"options"`
}

// Manager handles session operations
type Manager struct {
	cookieSessionName string
	mainDomainName    string
}

// NewManager creates a new session manager instance
//
// Parameters:
//   - cookieSessionName: Name of the session cookie
//   - mainDomainName: Domain name for the session cookie
//
// Returns:
//   - *Manager: Session manager instance
func NewManager(cookieSessionName, mainDomainName string) *Manager {
	if cookieSessionName == "" {
		cookieSessionName = "cnf.id"
	}
	if mainDomainName == "" {
		mainDomainName = "localhost"
	}
	
	return &Manager{
		cookieSessionName: cookieSessionName,
		mainDomainName:    mainDomainName,
	}
}

// SetSessionCookie sets a session cookie in the HTTP response.
// Creates a secure, HTTP-only cookie with the session ID for client-side session management.
//
// Parameters:
//   - c: Fiber context containing the HTTP response
//   - sessionID: The session identifier to store in the cookie
func (m *Manager) SetSessionCookie(c fiber.Ctx, sessionID string) {
	cookie := new(fiber.Cookie)
	cookie.Name = m.cookieSessionName
	cookie.Value = sessionID
	// Set Domain to a dot-prefixed base domain to cover all subdomains.
	cookie.Domain = fmt.Sprintf(".%s", m.mainDomainName)
	cookie.Path = "/"
	cookie.Expires = time.Now().Add(365 * 24 * time.Hour)
	cookie.HTTPOnly = true
	cookie.Secure = true
	c.Cookie(cookie)
}

// RemoveSessionCookie removes the session cookie from the HTTP response.
//
// Parameters:
//   - c: Fiber context containing the HTTP response
func (m *Manager) RemoveSessionCookie(c fiber.Ctx) {
	cookie := new(fiber.Cookie)
	cookie.Name = m.cookieSessionName
	cookie.Value = ""
	cookie.Domain = fmt.Sprintf(".%s", m.mainDomainName)
	cookie.Path = "/"
	cookie.Expires = time.Now().Add(-time.Hour)
	c.Cookie(cookie)
}

// GetSessionID gets the session ID from the cookie.
//
// Parameters:
//   - c: Fiber context containing the request
//
// Returns:
//   - string: The session ID
func (m *Manager) GetSessionID(c fiber.Ctx) string {
	return c.Cookies(m.cookieSessionName)
}

// GetCookieSessionName returns the name of the cookie session.
func (m *Manager) GetCookieSessionName() string {
	return m.cookieSessionName
}

// EnsureJSONField ensures a JSON field is not nil
func EnsureJSONField(field json.RawMessage, defaultValue string) json.RawMessage {
	if field == nil {
		return json.RawMessage(defaultValue)
	}
	return field
}

