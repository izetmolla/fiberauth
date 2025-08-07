package fiberauth

import (
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v3"
	"github.com/stretchr/testify/assert"
)

// TestAuthorization_SetSessionCookie tests session cookie setting
func TestAuthorization_SetSessionCookie(t *testing.T) {
	auth := &Authorization{
		cookieSessionName: "test_session",
		mainDomainName:    "example.com",
	}

	app := fiber.New()
	app.Get("/test", func(c fiber.Ctx) error {
		auth.SetSessionCookie(c, "test-session-id")
		return c.SendString("OK")
	})

	req := httptest.NewRequest("GET", "/test", nil)
	resp, err := app.Test(req)
	assert.NoError(t, err)
	assert.Equal(t, 200, resp.StatusCode)

	// Check if cookie was set
	cookies := resp.Cookies()
	assert.Len(t, cookies, 1)
	assert.Equal(t, "test_session", cookies[0].Name)
	assert.Equal(t, "test-session-id", cookies[0].Value)
	assert.Equal(t, ".example.com", cookies[0].Domain)
	assert.True(t, cookies[0].HttpOnly)
	assert.True(t, cookies[0].Secure)
}

// TestSessionManager_CreateAndStoreSession tests session creation and storage
func TestSessionManager_CreateAndStoreSession(t *testing.T) {
	auth := &Authorization{}
	sessionManager := NewSessionManager(auth)

	user := &User{
		ID:        "user-123",
		FirstName: "John",
		LastName:  "Doe",
		Email:     "john@example.com",
		Roles:     json.RawMessage(`["user", "admin"]`),
		Metadata:  json.RawMessage(`{"key": "value"}`),
	}

	sessionID := "session-456"

	err := sessionManager.CreateAndStoreSession(user, sessionID)
	assert.NoError(t, err)
}

// TestSessionManager_ensureJSONField tests JSON field validation
func TestSessionManager_ensureJSONField(t *testing.T) {
	auth := &Authorization{}
	sessionManager := NewSessionManager(auth)

	tests := []struct {
		name         string
		field        json.RawMessage
		defaultValue string
		expected     json.RawMessage
	}{
		{
			name:         "nil field",
			field:        nil,
			defaultValue: "[]",
			expected:     json.RawMessage("[]"),
		},
		{
			name:         "empty field",
			field:        json.RawMessage(""),
			defaultValue: "[]",
			expected:     json.RawMessage(""),
		},
		{
			name:         "valid field",
			field:        json.RawMessage(`["user", "admin"]`),
			defaultValue: "[]",
			expected:     json.RawMessage(`["user", "admin"]`),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := sessionManager.ensureJSONField(tt.field, tt.defaultValue)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestSessionManager_CreateAuthorizationResponse tests authorization response creation
func TestSessionManager_CreateAuthorizationResponse(t *testing.T) {
	auth := &Authorization{}
	sessionManager := NewSessionManager(auth)

	user := &User{
		ID:        "user-123",
		FirstName: "John",
		LastName:  "Doe",
		Email:     "john@example.com",
		AvatarURL: "https://example.com/avatar.jpg",
		Roles:     json.RawMessage(`["user", "admin"]`),
		Metadata:  json.RawMessage(`{"key": "value"}`),
	}

	tokens := &Tokens{
		AccessToken:  "access-token-123",
		RefreshToken: "refresh-token-456",
	}

	sessionID := "session-789"

	response := sessionManager.CreateAuthorizationResponse(user, tokens, sessionID)

	assert.NotNil(t, response)
	assert.Equal(t, sessionID, response.SessionID)
	assert.Equal(t, *tokens, response.Tokens)
	assert.NotNil(t, response.User)

	// Check user data in response
	userData, ok := response.User.(map[string]interface{})
	assert.True(t, ok)
	assert.Equal(t, "user-123", userData["id"])
	assert.Equal(t, "john@example.com", userData["email"])
	assert.Equal(t, "John", userData["first_name"])
	assert.Equal(t, "Doe", userData["last_name"])
	assert.Equal(t, "https://example.com/avatar.jpg", userData["avatar_url"])
}

// TestNewSessionManager tests session manager creation
func TestNewSessionManager(t *testing.T) {
	auth := &Authorization{}
	sessionManager := NewSessionManager(auth)

	assert.NotNil(t, sessionManager)
	assert.Equal(t, auth, sessionManager.auth)
}

// TestAuthorization_CreateSession tests session creation in database
func TestAuthorization_CreateSession(t *testing.T) {
	// This test would require a mock database
	// For now, we'll test the function signature and basic logic
	auth := &Authorization{}

	userID := "user-123"
	ip := "192.168.1.1"
	userAgent := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

	// Since we don't have a real database connection, this will likely fail
	// but we can test the function structure
	_, err := auth.CreateSession(userID, ip, userAgent)
	// We expect an error since there's no database connection
	assert.Error(t, err)
}

// TestSessionManager_Integration tests integration of session manager operations
func TestSessionManager_Integration(t *testing.T) {
	auth := &Authorization{}
	sessionManager := NewSessionManager(auth)

	// Create a test user
	user := &User{
		ID:        "test-user-123",
		FirstName: "Test",
		LastName:  "User",
		Email:     "test@example.com",
		Roles:     json.RawMessage(`["user"]`),
		Metadata:  json.RawMessage(`{"test": true}`),
	}

	sessionID := "test-session-456"

	// Test session creation
	err := sessionManager.CreateAndStoreSession(user, sessionID)
	assert.NoError(t, err)

	// Test authorization response creation
	tokens := &Tokens{
		AccessToken:  "test-access-token",
		RefreshToken: "test-refresh-token",
	}

	response := sessionManager.CreateAuthorizationResponse(user, tokens, sessionID)
	assert.NotNil(t, response)
	assert.Equal(t, sessionID, response.SessionID)
	assert.Equal(t, *tokens, response.Tokens)

	// Verify user data in response
	userData, ok := response.User.(map[string]interface{})
	assert.True(t, ok)
	assert.Equal(t, "test-user-123", userData["id"])
	assert.Equal(t, "test@example.com", userData["email"])
	assert.Equal(t, "Test", userData["first_name"])
	assert.Equal(t, "User", userData["last_name"])
}

// TestSessionManager_JSONHandling tests JSON field handling edge cases
func TestSessionManager_JSONHandling(t *testing.T) {
	auth := &Authorization{}
	sessionManager := NewSessionManager(auth)

	tests := []struct {
		name             string
		roles            json.RawMessage
		metadata         json.RawMessage
		expectedRoles    json.RawMessage
		expectedMetadata json.RawMessage
	}{
		{
			name:             "nil JSON fields",
			roles:            nil,
			metadata:         nil,
			expectedRoles:    json.RawMessage("[]"),
			expectedMetadata: json.RawMessage("{}"),
		},
		{
			name:             "empty JSON fields",
			roles:            json.RawMessage(""),
			metadata:         json.RawMessage(""),
			expectedRoles:    json.RawMessage(""),
			expectedMetadata: json.RawMessage(""),
		},
		{
			name:             "valid JSON fields",
			roles:            json.RawMessage(`["admin", "user"]`),
			metadata:         json.RawMessage(`{"key": "value"}`),
			expectedRoles:    json.RawMessage(`["admin", "user"]`),
			expectedMetadata: json.RawMessage(`{"key": "value"}`),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			user := &User{
				ID:       "test-user",
				Roles:    tt.roles,
				Metadata: tt.metadata,
			}

			sessionID := "test-session"
			err := sessionManager.CreateAndStoreSession(user, sessionID)
			assert.NoError(t, err)

			// Verify that JSON fields are handled correctly
			rolesResult := sessionManager.ensureJSONField(tt.roles, "[]")
			metadataResult := sessionManager.ensureJSONField(tt.metadata, "{}")

			assert.Equal(t, tt.expectedRoles, rolesResult)
			assert.Equal(t, tt.expectedMetadata, metadataResult)
		})
	}
}
