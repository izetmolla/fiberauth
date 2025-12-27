// Package validation provides input validation utilities for authentication.
// This package has minimal dependencies and can be imported independently.
package validation

import (
	"errors"
	"fmt"
	"strings"
)

// ValidationError represents a validation error with field information
type ValidationError struct {
	Field   string
	Message string
}

func (v *ValidationError) Error() string {
	return fmt.Sprintf("%s: %s", v.Field, v.Message)
}

// Validator handles common validation operations
type Validator struct {
	MinPasswordLength int
}

// NewValidator creates a new validator instance with default settings
func NewValidator() *Validator {
	return &Validator{
		MinPasswordLength: 6,
	}
}

// ValidateRequired validates that a field is not empty
func (v *Validator) ValidateRequired(value, fieldName string) error {
	if strings.TrimSpace(value) == "" {
		return &ValidationError{Field: fieldName, Message: fmt.Sprintf("%s is required", fieldName)}
	}
	return nil
}

// ValidateEmail validates email format
func (v *Validator) ValidateEmail(email string) error {
	if email == "" {
		return &ValidationError{Field: "email", Message: "email is required"}
	}

	// Basic email validation
	if !strings.Contains(email, "@") || !strings.Contains(email, ".") {
		return &ValidationError{Field: "email", Message: "invalid email format"}
	}

	// Split email into local and domain parts
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return &ValidationError{Field: "email", Message: "invalid email format"}
	}

	localPart := parts[0]
	domainPart := parts[1]

	// Check if local part is empty
	if strings.TrimSpace(localPart) == "" {
		return &ValidationError{Field: "email", Message: "invalid email format"}
	}

	// Check if domain part is empty or doesn't contain a dot
	if strings.TrimSpace(domainPart) == "" || !strings.Contains(domainPart, ".") {
		return &ValidationError{Field: "email", Message: "invalid email format"}
	}

	return nil
}

// ValidatePassword validates password strength.
//
// Parameters:
//   - password: The password to validate
//
// Returns:
//   - error: ValidationError if password is empty or too short, nil if valid
func (v *Validator) ValidatePassword(password string) error {
	if password == "" {
		return &ValidationError{Field: "password", Message: "password is required"}
	}

	// Minimum password length validation
	minLength := v.MinPasswordLength
	if minLength == 0 {
		minLength = 6
	}
	
	if len(password) < minLength {
		return &ValidationError{Field: "password", Message: fmt.Sprintf("password must be at least %d characters", minLength)}
	}

	return nil
}

// ValidateSignInEmailOrUsername validates that either email or username is provided.
//
// Parameters:
//   - email: The email address
//   - username: The username
//
// Returns:
//   - error: Error if both email and username are empty
func (v *Validator) ValidateSignInEmailOrUsername(email, username string) error {
	if email == "" && username == "" {
		return errors.New("email or username is required")
	}
	return nil
}

