package fiberauth

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestNew tests authorization initialization
func TestNew(t *testing.T) {
	tests := []struct {
		name        string
		config      *Config
		expectError bool
	}{
		{
			name: "valid configuration",
			config: &Config{
				JWTSecret: "test-secret-key",
			},
			expectError: false,
		},
		{
			name: "empty JWT secret",
			config: &Config{
				JWTSecret: "",
			},
			expectError: true,
		},
		{
			name:        "nil configuration",
			config:      nil,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			auth, err := New(tt.config)

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, auth)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, auth)
				assert.Equal(t, tt.config.JWTSecret, auth.GetJWTSecret())
			}
		})
	}
}

// TestAuthorization_GetJWTSecret tests JWT secret retrieval
func TestAuthorization_GetJWTSecret(t *testing.T) {
	expectedSecret := "test-secret-key"
	auth := &Authorization{
		jwtSecret: expectedSecret,
	}

	result := auth.GetJWTSecret()
	assert.Equal(t, expectedSecret, result)
}

// TestAuthorization_DefaultValues tests default value setting
func TestAuthorization_DefaultValues(t *testing.T) {
	auth := &Authorization{}
	auth.setDefaults()

	// Test that default values are set
	assert.NotNil(t, auth.accessTokenLifetime)
	assert.NotNil(t, auth.refreshTokenLifetime)
	assert.NotNil(t, auth.signingMethodHMAC)
	assert.NotZero(t, auth.redisTTL)
	assert.NotEmpty(t, auth.redisPrefix)
}

// TestAuthorization_Configuration tests configuration application
func TestAuthorization_Configuration(t *testing.T) {
	config := &Config{
		JWTSecret: "test-secret-key",
		Debug:     true,
	}

	auth := &Authorization{}
	auth.applyConfig(config)

	assert.Equal(t, config.JWTSecret, auth.jwtSecret)
}

// TestAuthorization_Initialization tests full initialization process
func TestAuthorization_Initialization(t *testing.T) {
	config := &Config{
		JWTSecret: "test-secret-key",
		Debug:     true,
	}

	auth, err := New(config)
	assert.NoError(t, err)
	assert.NotNil(t, auth)

	// Verify that configuration was applied
	assert.Equal(t, config.JWTSecret, auth.GetJWTSecret())
	assert.Equal(t, config.Debug, auth.Debug)

	// Verify that defaults were set
	assert.NotNil(t, auth.accessTokenLifetime)
	assert.NotNil(t, auth.refreshTokenLifetime)
	assert.NotNil(t, auth.signingMethodHMAC)
}

// TestAuthorization_EmptyConfig tests behavior with minimal configuration
func TestAuthorization_EmptyConfig(t *testing.T) {
	config := &Config{
		JWTSecret: "minimal-secret",
	}

	auth, err := New(config)
	assert.NoError(t, err)
	assert.NotNil(t, auth)

	// Verify that required fields are set
	assert.Equal(t, config.JWTSecret, auth.GetJWTSecret())
	assert.NotNil(t, auth.accessTokenLifetime)
	assert.NotNil(t, auth.refreshTokenLifetime)
	assert.NotNil(t, auth.signingMethodHMAC)
}

// TestAuthorization_DebugMode tests debug mode functionality
func TestAuthorization_DebugMode(t *testing.T) {
	config := &Config{
		JWTSecret: "test-secret-key",
		Debug:     true,
	}

	auth, err := New(config)
	assert.NoError(t, err)
	assert.True(t, auth.Debug)

	// Test with debug disabled
	config.Debug = false
	auth2, err := New(config)
	assert.NoError(t, err)
	assert.False(t, auth2.Debug)
}

// TestAuthorization_ConfigurationValidation tests configuration validation
func TestAuthorization_ConfigurationValidation(t *testing.T) {
	tests := []struct {
		name        string
		config      *Config
		expectError bool
		errorMsg    string
	}{
		{
			name: "valid configuration",
			config: &Config{
				JWTSecret: "valid-secret",
			},
			expectError: false,
		},
		{
			name: "empty JWT secret",
			config: &Config{
				JWTSecret: "",
			},
			expectError: true,
			errorMsg:    "JWT_SECRET secret cannot be empty",
		},
		{
			name:        "nil configuration",
			config:      nil,
			expectError: true,
			errorMsg:    "JWT_SECRET secret cannot be empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			auth, err := New(tt.config)

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, auth)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, auth)
			}
		})
	}
}

// TestAuthorization_StructFields tests that all required fields are present
func TestAuthorization_StructFields(t *testing.T) {
	auth := &Authorization{}

	// Test that all required fields exist (this is a compile-time check)
	// If any of these fields don't exist, the test will fail to compile
	_ = auth.Debug
	_ = auth.jwtSecret
	_ = auth.sqlStorage
	_ = auth.redisStorage
	_ = auth.redisPrefix
	_ = auth.redisTTL
	_ = auth.accessTokenLifetime
	_ = auth.refreshTokenLifetime
	_ = auth.signingMethodHMAC
	_ = auth.cookieSessionName
	_ = auth.mainDomainName
	_ = auth.authRedirectURL
	_ = auth.social
	_ = auth.providers
}
