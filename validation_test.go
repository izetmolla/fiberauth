package fiberauth

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestValidator_ValidateRequired tests required field validation
func TestValidator_ValidateRequired(t *testing.T) {
	validator := NewValidator()

	tests := []struct {
		name      string
		value     string
		fieldName string
		expectErr bool
	}{
		{
			name:      "valid required field",
			value:     "test value",
			fieldName: "test_field",
			expectErr: false,
		},
		{
			name:      "empty required field",
			value:     "",
			fieldName: "test_field",
			expectErr: true,
		},
		{
			name:      "whitespace only field",
			value:     "   ",
			fieldName: "test_field",
			expectErr: true,
		},
		{
			name:      "tab only field",
			value:     "\t",
			fieldName: "test_field",
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validator.ValidateRequired(tt.value, tt.fieldName)

			if tt.expectErr {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.fieldName)
				assert.Contains(t, err.Error(), "required")
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestValidator_ValidateEmail tests email validation
func TestValidator_ValidateEmail(t *testing.T) {
	validator := NewValidator()

	tests := []struct {
		name      string
		email     string
		expectErr bool
	}{
		{
			name:      "valid email",
			email:     "test@example.com",
			expectErr: false,
		},
		{
			name:      "valid email with subdomain",
			email:     "test@sub.example.com",
			expectErr: false,
		},
		{
			name:      "valid email with plus",
			email:     "test+tag@example.com",
			expectErr: false,
		},
		{
			name:      "empty email",
			email:     "",
			expectErr: true,
		},
		{
			name:      "missing @ symbol",
			email:     "testexample.com",
			expectErr: true,
		},
		{
			name:      "missing domain",
			email:     "test@",
			expectErr: true,
		},
		{
			name:      "missing local part",
			email:     "@example.com",
			expectErr: true,
		},
		{
			name:      "no dot in domain",
			email:     "test@example",
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validator.ValidateEmail(tt.email)

			if tt.expectErr {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "email")
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestValidator_ValidatePassword tests password validation
func TestValidator_ValidatePassword(t *testing.T) {
	validator := NewValidator()

	tests := []struct {
		name      string
		password  string
		expectErr bool
	}{
		{
			name:      "valid password",
			password:  "password123",
			expectErr: false,
		},
		{
			name:      "valid password with special chars",
			password:  "pass@word123!",
			expectErr: false,
		},
		{
			name:      "valid password minimum length",
			password:  "123456",
			expectErr: false,
		},
		{
			name:      "empty password",
			password:  "",
			expectErr: true,
		},
		{
			name:      "password too short",
			password:  "12345",
			expectErr: true,
		},
		{
			name:      "password with spaces",
			password:  "pass word",
			expectErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validator.ValidatePassword(tt.password)

			if tt.expectErr {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "password")
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestValidator_ValidateSignUpRequest tests sign up request validation
func TestValidator_ValidateSignUpRequest(t *testing.T) {
	validator := NewValidator()

	tests := []struct {
		name       string
		request    *SignUpRequest
		expectErr  bool
		errorField string
	}{
		{
			name: "valid sign up request",
			request: &SignUpRequest{
				FirstName: "John",
				LastName:  "Doe",
				Email:     "john@example.com",
				Password:  "password123",
			},
			expectErr: false,
		},
		{
			name: "missing first name",
			request: &SignUpRequest{
				FirstName: "",
				LastName:  "Doe",
				Email:     "john@example.com",
				Password:  "password123",
			},
			expectErr:  true,
			errorField: "first_name",
		},
		{
			name: "missing last name",
			request: &SignUpRequest{
				FirstName: "John",
				LastName:  "",
				Email:     "john@example.com",
				Password:  "password123",
			},
			expectErr:  true,
			errorField: "last_name",
		},
		{
			name: "invalid email",
			request: &SignUpRequest{
				FirstName: "John",
				LastName:  "Doe",
				Email:     "invalid-email",
				Password:  "password123",
			},
			expectErr:  true,
			errorField: "email",
		},
		{
			name: "password too short",
			request: &SignUpRequest{
				FirstName: "John",
				LastName:  "Doe",
				Email:     "john@example.com",
				Password:  "123",
			},
			expectErr:  true,
			errorField: "password",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validator.ValidateSignUpRequest(tt.request)

			if tt.expectErr {
				assert.NotNil(t, err)
				if tt.errorField != "" {
					assert.Equal(t, tt.errorField, err.Field)
				}
			} else {
				assert.Nil(t, err)
			}
		})
	}
}

// TestValidator_ValidateSignInRequest tests sign in request validation
func TestValidator_ValidateSignInRequest(t *testing.T) {
	validator := NewValidator()

	tests := []struct {
		name       string
		request    *SignInRequest
		expectErr  bool
		errorField string
	}{
		{
			name: "valid sign in with email",
			request: &SignInRequest{
				Email:    "john@example.com",
				Password: "password123",
			},
			expectErr: false,
		},
		{
			name: "valid sign in with username",
			request: &SignInRequest{
				Username: "john_doe",
				Password: "password123",
			},
			expectErr: false,
		},
		{
			name: "missing email and username",
			request: &SignInRequest{
				Email:    "",
				Username: "",
				Password: "password123",
			},
			expectErr:  true,
			errorField: "email",
		},
		{
			name: "missing password",
			request: &SignInRequest{
				Email:    "john@example.com",
				Password: "",
			},
			expectErr:  true,
			errorField: "password",
		},
		{
			name: "password too short",
			request: &SignInRequest{
				Email:    "john@example.com",
				Password: "123",
			},
			expectErr:  true,
			errorField: "password",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validator.ValidateSignInRequest(tt.request)

			if tt.expectErr {
				assert.NotNil(t, err)
				if tt.errorField != "" {
					assert.Equal(t, tt.errorField, err.Field)
				}
			} else {
				assert.Nil(t, err)
			}
		})
	}
}

// TestValidationError_Error tests validation error formatting
func TestValidationError_Error(t *testing.T) {
	tests := []struct {
		name     string
		field    string
		message  string
		expected string
	}{
		{
			name:     "simple validation error",
			field:    "email",
			message:  "invalid format",
			expected: "email: invalid format",
		},
		{
			name:     "required field error",
			field:    "password",
			message:  "password is required",
			expected: "password: password is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := &ValidationError{
				Field:   tt.field,
				Message: tt.message,
			}

			assert.Equal(t, tt.expected, err.Error())
		})
	}
}
