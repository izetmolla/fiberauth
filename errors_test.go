package fiberauth

import (
	"errors"
	"testing"

	"github.com/gofiber/fiber/v3"
	"github.com/stretchr/testify/assert"
)

// TestErrorFields tests ErrorFields struct functionality
func TestErrorFields(t *testing.T) {
	tests := []struct {
		name      string
		err       error
		field     string
		expectNil bool
	}{
		{
			name:      "error with field",
			err:       errors.New("test error"),
			field:     "email",
			expectNil: false,
		},
		{
			name:      "error without field",
			err:       errors.New("test error"),
			field:     "",
			expectNil: false,
		},
		{
			name:      "nil error",
			err:       nil,
			field:     "email",
			expectNil: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errorFields := &ErrorFields{
				Error: tt.err,
				Field: tt.field,
			}

			if tt.expectNil {
				assert.Nil(t, errorFields.Error)
			} else {
				assert.NotNil(t, errorFields.Error)
				assert.Equal(t, tt.err.Error(), errorFields.Error.Error())
			}
			assert.Equal(t, tt.field, errorFields.Field)
		})
	}
}

// TestAuthorization_ErrorJSON tests ErrorJSON functionality
func TestAuthorization_ErrorJSON(t *testing.T) {
	auth := &Authorization{}

	tests := []struct {
		name     string
		err      error
		field    string
		expected fiber.Map
	}{
		{
			name:  "error with field",
			err:   errors.New("invalid email"),
			field: "email",
			expected: fiber.Map{
				"error": fiber.Map{
					"message": "invalid email",
					"field":   "email",
				},
			},
		},
		{
			name:  "error without field",
			err:   errors.New("invalid token"),
			field: "",
			expected: fiber.Map{
				"error": fiber.Map{
					"message": "invalid token",
				},
			},
		},
		{
			name:  "nil error",
			err:   nil,
			field: "",
			expected: fiber.Map{
				"error": fiber.Map{
					"message": "",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var result fiber.Map
			if tt.field != "" {
				result = auth.ErrorJSON(tt.err, tt.field)
			} else {
				result = auth.ErrorJSON(tt.err)
			}

			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestAuthorization_JSONErrorString tests JSONErrorString functionality
func TestAuthorization_JSONErrorString(t *testing.T) {
	auth := &Authorization{}

	tests := []struct {
		name     string
		err      error
		expected string
	}{
		{
			name:     "simple error",
			err:      errors.New("invalid credentials"),
			expected: `{"error":{"message":"invalid credentials"}}`,
		},
		{
			name:     "error with special characters",
			err:      errors.New("invalid email: test@example"),
			expected: `{"error":{"message":"invalid email: test@example"}}`,
		},
		{
			name:     "nil error",
			err:      nil,
			expected: `{"error":{"message":""}}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := auth.JSONErrorString(tt.err)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestErrorConstants tests predefined error constants
func TestErrorConstants(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected string
	}{
		{
			name:     "ErrInvalidCredentials",
			err:      ErrInvalidCredentials,
			expected: "invalid credentials",
		},
		{
			name:     "ErrUserNotFound",
			err:      ErrUserNotFound,
			expected: "user not found",
		},
		{
			name:     "ErrUserAlreadyExists",
			err:      ErrUserAlreadyExists,
			expected: "user already exists",
		},
		{
			name:     "ErrInvalidToken",
			err:      ErrInvalidToken,
			expected: "invalid token",
		},
		{
			name:     "ErrTokenExpired",
			err:      ErrTokenExpired,
			expected: "token expired",
		},
		{
			name:     "ErrUnauthorized",
			err:      ErrUnauthorized,
			expected: "unauthorized",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.err.Error())
		})
	}
}

// TestErrorFields_Integration tests integration of error handling
func TestErrorFields_Integration(t *testing.T) {
	auth := &Authorization{}

	// Test creating an error with field information
	errorFields := &ErrorFields{
		Error: ErrInvalidCredentials,
		Field: "password",
	}

	// Test ErrorJSON with field
	errorJSON := auth.ErrorJSON(errorFields.Error, errorFields.Field)
	expectedJSON := fiber.Map{
		"error": fiber.Map{
			"message": "invalid credentials",
			"field":   "password",
		},
	}
	assert.Equal(t, expectedJSON, errorJSON)

	// Test JSONErrorString
	errorString := auth.JSONErrorString(errorFields.Error)
	expectedString := `{"error":{"message":"invalid credentials"}}`
	assert.Equal(t, expectedString, errorString)
}

// TestErrorFields_FieldValidation tests field validation in errors
func TestErrorFields_FieldValidation(t *testing.T) {
	tests := []struct {
		name        string
		errorFields *ErrorFields
		hasField    bool
	}{
		{
			name: "error with field",
			errorFields: &ErrorFields{
				Error: errors.New("test error"),
				Field: "email",
			},
			hasField: true,
		},
		{
			name: "error without field",
			errorFields: &ErrorFields{
				Error: errors.New("test error"),
				Field: "",
			},
			hasField: false,
		},
		{
			name: "error with empty field",
			errorFields: &ErrorFields{
				Error: errors.New("test error"),
				Field: "   ",
			},
			hasField: true, // Empty string is still a field
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.hasField {
				assert.NotEmpty(t, tt.errorFields.Field)
			} else {
				assert.Empty(t, tt.errorFields.Field)
			}
		})
	}
}

// TestErrorJSON_EdgeCases tests edge cases for ErrorJSON
func TestErrorJSON_EdgeCases(t *testing.T) {
	auth := &Authorization{}

	tests := []struct {
		name     string
		err      error
		fields   []string
		expected fiber.Map
	}{
		{
			name:   "multiple fields (should use first)",
			err:    errors.New("test error"),
			fields: []string{"field1", "field2", "field3"},
			expected: fiber.Map{
				"error": fiber.Map{
					"message": "test error",
					"field":   "field1",
				},
			},
		},
		{
			name:   "empty fields slice",
			err:    errors.New("test error"),
			fields: []string{},
			expected: fiber.Map{
				"error": fiber.Map{
					"message": "test error",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var result fiber.Map
			if len(tt.fields) > 0 {
				result = auth.ErrorJSON(tt.err, tt.fields...)
			} else {
				result = auth.ErrorJSON(tt.err)
			}

			assert.Equal(t, tt.expected, result)
		})
	}
}
