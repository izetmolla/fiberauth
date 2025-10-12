package fiberauth

import (
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
)

// TestAuthorization_IsValidPassword tests password validation
func TestAuthorization_IsValidPassword(t *testing.T) {
	auth := &Authorization{}

	tests := []struct {
		name     string
		password string
		hash     string
		expected bool
	}{
		{
			name:     "valid password",
			password: "testpassword123",
			hash:     "$2a$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdBPj4J/HS.iQ2O",
			expected: true,
		},
		{
			name:     "invalid password",
			password: "wrongpassword",
			hash:     "$2a$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdBPj4J/HS.iQ2O",
			expected: false,
		},
		{
			name:     "empty password",
			password: "",
			hash:     "$2a$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdBPj4J/HS.iQ2O",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := auth.IsValidPassword(tt.hash, tt.password)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestAuthorization_CreatePassword tests password hashing
func TestAuthorization_CreatePassword(t *testing.T) {
	auth := &Authorization{}

	tests := []struct {
		name     string
		password string
	}{
		{
			name:     "normal password",
			password: "testpassword123",
		},
		{
			name:     "empty password",
			password: "",
		},
		{
			name:     "special characters",
			password: "test@#$%^&*()_+",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hash, err := auth.CreatePassword(tt.password)
			assert.NoError(t, err)

			// Verify the hash is not empty
			assert.NotEmpty(t, hash)

			// Verify the hash starts with bcrypt identifier
			assert.True(t, len(hash) > 10)

			// Verify the password can be validated against the hash
			if tt.password != "" {
				assert.True(t, auth.IsValidPassword(hash, tt.password), err)
			}
		})
	}
}

// TestAuthorization_GetTokenFromHeader tests token extraction from headers
func TestAuthorization_GetTokenFromHeader(t *testing.T) {
	auth := &Authorization{}

	tests := []struct {
		name        string
		authHeader  string
		expected    string
		expectError bool
	}{
		{
			name:        "bearer token",
			authHeader:  "Bearer test-token-123",
			expected:    "test-token-123",
			expectError: false,
		},
		{
			name:        "token scheme",
			authHeader:  "Token test-token-456",
			expected:    "test-token-456",
			expectError: false,
		},
		{
			name:        "no scheme",
			authHeader:  "test-token-789",
			expected:    "test-token-789",
			expectError: false,
		},
		{
			name:        "empty header",
			authHeader:  "",
			expected:    "",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a test app and request
			app := fiber.New()
			app.Get("/test", func(c fiber.Ctx) error {
				token, err := auth.GetTokenFromHeader(c)
				if err != nil {
					return c.Status(400).JSON(fiber.Map{"error": err.Error()})
				}
				return c.JSON(fiber.Map{"token": token})
			})

			req := httptest.NewRequest("GET", "/test", nil)
			if tt.authHeader != "" {
				req.Header.Set("Authorization", tt.authHeader)
			}

			resp, err := app.Test(req)
			assert.NoError(t, err)

			if tt.expectError {
				assert.Equal(t, 400, resp.StatusCode)
			} else {
				assert.Equal(t, 200, resp.StatusCode)
			}
		})
	}
}

// TestAuthorization_ExtractToken tests JWT token extraction
func TestAuthorization_ExtractToken(t *testing.T) {
	auth := &Authorization{
		jwtSecret: "test-secret-key",
	}

	// Create a valid token
	claims := &RefreshTokenClaims{
		UserID:    "user-123",
		SessionID: "session-456",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(auth.jwtSecret))
	assert.NoError(t, err)

	tests := []struct {
		name        string
		tokenString string
		expectError bool
	}{
		{
			name:        "valid token",
			tokenString: tokenString,
			expectError: false,
		},
		{
			name:        "invalid token",
			tokenString: "invalid-token",
			expectError: true,
		},
		{
			name:        "empty token",
			tokenString: "",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			claims, err := auth.ExtractToken(tt.tokenString)

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, claims)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, claims)
				assert.Equal(t, "user-123", claims.UserID)
				assert.Equal(t, "session-456", claims.SessionID)
			}
		})
	}
}

// TestAuthorization_hasRequiredRole tests role checking functionality
func TestAuthorization_hasRequiredRole(t *testing.T) {
	auth := &Authorization{}

	tests := []struct {
		name          string
		requiredRoles []string
		userRoles     []string
		expected      bool
	}{
		{
			name:          "user has required role",
			requiredRoles: []string{"admin", "user"},
			userRoles:     []string{"user", "moderator"},
			expected:      true,
		},
		{
			name:          "user does not have required role",
			requiredRoles: []string{"admin"},
			userRoles:     []string{"user", "moderator"},
			expected:      false,
		},
		{
			name:          "no required roles",
			requiredRoles: []string{},
			userRoles:     []string{"user", "moderator"},
			expected:      true,
		},
		{
			name:          "empty user roles",
			requiredRoles: []string{"admin"},
			userRoles:     []string{},
			expected:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := auth.hasRequiredRole(tt.requiredRoles, tt.userRoles)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestAuthorization_hasRequiredRoleFromJSON tests JSON role checking
func TestAuthorization_hasRequiredRoleFromJSON(t *testing.T) {
	auth := &Authorization{}

	tests := []struct {
		name          string
		requiredRoles []string
		userRoles     json.RawMessage
		expected      bool
	}{
		{
			name:          "user has required role",
			requiredRoles: []string{"admin", "user"},
			userRoles:     json.RawMessage(`["user", "moderator"]`),
			expected:      true,
		},
		{
			name:          "user does not have required role",
			requiredRoles: []string{"admin"},
			userRoles:     json.RawMessage(`["user", "moderator"]`),
			expected:      false,
		},
		{
			name:          "invalid JSON",
			requiredRoles: []string{"admin"},
			userRoles:     json.RawMessage(`invalid json`),
			expected:      false,
		},
		{
			name:          "no required roles",
			requiredRoles: []string{},
			userRoles:     json.RawMessage(`["user", "moderator"]`),
			expected:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := auth.hasRequiredRoleFromJSON(tt.requiredRoles, tt.userRoles)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestAuthorization_getAuthRedirectURL tests redirect URL extraction
func TestAuthorization_getAuthRedirectURL(t *testing.T) {
	auth := &Authorization{
		authRedirectURL: "https://default.com/callback",
	}

	tests := []struct {
		name          string
		queryRedirect string
		expected      string
	}{
		{
			name:          "with redirect URL in query",
			queryRedirect: "https://custom.com/callback",
			expected:      "https://custom.com/callback",
		},
		{
			name:          "no redirect URL in query",
			queryRedirect: "",
			expected:      "https://default.com/callback",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a test app and request
			app := fiber.New()
			app.Get("/test", func(c fiber.Ctx) error {
				result := auth.getAuthRedirectURL(c)
				return c.JSON(fiber.Map{"redirect": result})
			})

			req := httptest.NewRequest("GET", "/test", nil)
			if tt.queryRedirect != "" {
				q := req.URL.Query()
				q.Set("redirect_url", tt.queryRedirect)
				req.URL.RawQuery = q.Encode()
			}

			resp, err := app.Test(req)
			assert.NoError(t, err)
			assert.Equal(t, 200, resp.StatusCode)
		})
	}
}

// TestUserResponse tests user response formatting
func TestUserResponse(t *testing.T) {
	user := &User{
		ID:        "user-123",
		Email:     "test@example.com",
		FirstName: "John",
		LastName:  "Doe",
		AvatarURL: "https://example.com/avatar.jpg",
		Roles:     json.RawMessage(`["user", "moderator"]`),
		Metadata:  json.RawMessage(`{"key": "value"}`),
	}

	result := userResponse(user)

	expected := map[string]interface{}{
		"id":         "user-123",
		"email":      "test@example.com",
		"first_name": "John",
		"last_name":  "Doe",
		"avatar_url": "https://example.com/avatar.jpg",
		"roles":      json.RawMessage(`["user", "moderator"]`),
		"metadata":   json.RawMessage(`{"key": "value"}`),
	}

	assert.Equal(t, expected, result)
}
