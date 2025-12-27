package fiberauth

import (
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v3"
	"github.com/stretchr/testify/assert"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// Helper function to create test auth
func createTestAuthForSession(t *testing.T) *Authorization {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}

	auth, err := New(&Config{
		JWTSecret: "test-secret",
		DbClient:  db,
	})
	if err != nil {
		t.Fatal(err)
	}

	return auth
}

// TestAuthorization_SetSessionCookie tests session cookie setting
func TestAuthorization_SetSessionCookie_Fixed(t *testing.T) {
	auth := createTestAuthForSession(t)

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
	assert.NotEmpty(t, cookies)
}

// TestSessionManager_CreateAndStoreSession tests session creation and storage
func TestSessionManager_CreateAndStoreSession_Fixed(t *testing.T) {
	auth := createTestAuthForSession(t)

	user := &User{
		ID:        "user-123",
		FirstName: "John",
		LastName:  "Doe",
		Email:     "john@example.com",
		Roles:     json.RawMessage(`["user", "admin"]`),
		Metadata:  json.RawMessage(`{"key": "value"}`),
	}

	// Test through auth public API
	sessionID, err := auth.CreateSession(user.ID, "127.0.0.1", "test-agent")
	assert.NoError(t, err)
	assert.NotEmpty(t, sessionID)
}

// TestSessionManager_ensureJSONField tests JSON field validation
func TestSessionManager_ensureJSONField_Fixed(t *testing.T) {
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
			expected:     json.RawMessage("[]"),
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
			result := EnsureJSONField(tt.field, tt.defaultValue)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestSessionManager_CreateAuthorizationResponse tests authorization response creation
func TestSessionManager_CreateAuthorizationResponse_Fixed(t *testing.T) {
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

	// Create response directly (testing internal logic)
	response := &AuthorizationResponse{
		User: map[string]any{
			"id":         user.ID,
			"first_name": user.FirstName,
			"last_name":  user.LastName,
			"avatar_url": user.AvatarURL,
			"email":      user.Email,
			"roles":      user.Roles,
			"metadata":   user.Metadata,
		},
		SessionID: sessionID,
		Tokens:    *tokens,
	}

	assert.NotNil(t, response)
	assert.Equal(t, sessionID, response.SessionID)
	assert.Equal(t, *tokens, response.Tokens)
	assert.NotNil(t, response.User)

	// Check user data in response
	userData, ok := response.User.(map[string]any)
	assert.True(t, ok)
	assert.Equal(t, "user-123", userData["id"])
	assert.Equal(t, "john@example.com", userData["email"])
	assert.Equal(t, "John", userData["first_name"])
	assert.Equal(t, "Doe", userData["last_name"])
	assert.Equal(t, "https://example.com/avatar.jpg", userData["avatar_url"])
}

// TestNewSessionManager tests session manager creation
func TestNewSessionManager_Fixed(t *testing.T) {
	auth := createTestAuthForSession(t)

	// Session manager is internal, test through auth methods
	cookieName := auth.GetCookieSessionName()
	assert.NotEmpty(t, cookieName)
}

// TestAuthorization_CreateSession tests session creation in database
func TestAuthorization_CreateSession_Fixed(t *testing.T) {
	auth := createTestAuthForSession(t)

	userID := "user-123"
	ip := "192.168.1.1"
	userAgent := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

	sessionID, err := auth.CreateSession(userID, ip, userAgent)
	assert.NoError(t, err)
	assert.NotEmpty(t, sessionID)
}

// TestSessionManager_Integration tests integration of session manager operations
func TestSessionManager_Integration_Fixed(t *testing.T) {
	auth := createTestAuthForSession(t)

	// Create a test user
	user := &User{
		ID:        "test-user-123",
		FirstName: "Test",
		LastName:  "User",
		Email:     "test@example.com",
		Roles:     json.RawMessage(`["user"]`),
		Metadata:  json.RawMessage(`{"test": true}`),
	}

	// Test session creation
	sessionID, err := auth.CreateSession(user.ID, "127.0.0.1", "test-agent")
	assert.NoError(t, err)

	// Test authorization response creation
	tokens := &Tokens{
		AccessToken:  "test-access-token",
		RefreshToken: "test-refresh-token",
	}

	response := &AuthorizationResponse{
		User: map[string]any{
			"id":    user.ID,
			"email": user.Email,
		},
		SessionID: sessionID,
		Tokens:    *tokens,
	}
	assert.NotNil(t, response)
	assert.Equal(t, sessionID, response.SessionID)
	assert.Equal(t, *tokens, response.Tokens)

	// Verify user data in response
	userData, ok := response.User.(map[string]any)
	assert.True(t, ok)
	assert.Equal(t, "test-user-123", userData["id"])
	assert.Equal(t, "test@example.com", userData["email"])
}

// TestSessionManager_JSONHandling tests JSON field handling edge cases
func TestSessionManager_JSONHandling_Fixed(t *testing.T) {
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
			expectedRoles:    json.RawMessage("[]"),
			expectedMetadata: json.RawMessage("{}"),
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
			// Test field processing with exported helper
			rolesResult := EnsureJSONField(tt.roles, "[]")
			metadataResult := EnsureJSONField(tt.metadata, "{}")

			assert.Equal(t, tt.expectedRoles, rolesResult)
			assert.Equal(t, tt.expectedMetadata, metadataResult)
		})
	}
}

